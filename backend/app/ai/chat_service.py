from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from pymongo.database import Database

from backend.app import config
from backend.app.ai.context_manager import load_scanner_evidence, scanner_context_requested
from backend.app.ai.prompt_builder import build_prompt, remove_unknown_citation_tags
from backend.app.ai.provider_factory import get_provider
from backend.app.ai.providers.base import LLMProvider, ProviderError
from backend.app.ai.system_prompt import SECURITY_ANALYST_SYSTEM_PROMPT
from backend.app.knowledge.service import search_documents
from backend.app.intelligence.search import list_relationships, search_intelligence

logger = logging.getLogger(__name__)
_INTELLIGENCE_IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ChatTurn:
    answer: str
    citations: list[dict[str, Any]]
    scanner_sources: list[dict[str, Any]]
    provider: str
    model: str
    token_usage: dict[str, int] | None
    rag_enabled: bool


def _select_citations(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen_sources: set[tuple[str, int | None]] = set()
    for result in results:
        try:
            score = float(result.get("relevance_score", 0.0))
        except (ValueError, TypeError):
            continue
        if score < config.CHAT_RAG_MIN_SIMILARITY:
            continue
        doc_id = str(result.get("document_id") or "")
        source_key = (doc_id, result.get("page_number"))
        if not doc_id or source_key in seen_sources:
            continue
        seen_sources.add(source_key)
        selected.append({
            "citation_id": f"S{len(selected) + 1}", "document_id": doc_id,
            "title": str(result.get("filename") or result.get("source") or "Untitled document"),
            "source": str(result.get("source") or result.get("filename") or "Unknown source"),
            "page_number": result.get("page_number"),
            "chunk_index": result.get("chunk_index"),
            "excerpt": str(result.get("excerpt") or "")[:2000],
            "relevance_score": score,
        })
    return selected


def _source_urls(record: dict[str, Any], relationships: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []

    def add(value: Any) -> None:
        if isinstance(value, str) and value.startswith(("https://", "http://")) and value not in urls:
            urls.append(value[:1000])
        elif isinstance(value, dict):
            add(value.get("url"))
        elif isinstance(value, (list, tuple)):
            for child in value:
                add(child)

    for field in ("source_url", "source_references", "references", "source_provenance"):
        add(record.get(field))
    for relationship in relationships:
        add(relationship.get("source_references"))
        add(relationship.get("evidence"))
    return urls[:5]


def _bounded_intel_value(value: Any) -> Any:
    if isinstance(value, str):
        return value[:300]
    if isinstance(value, list):
        return [_bounded_intel_value(item) for item in value[:10]]
    if isinstance(value, dict):
        return {str(key)[:80]: _bounded_intel_value(item)
                for key, item in list(value.items())[:10]}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:300]


def _bounded_relationships(relationships: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    bounded = []
    for relation in relationships[:limit]:
        row: dict[str, Any] = {}
        for key in ("source", "target"):
            endpoint = relation.get(key)
            if isinstance(endpoint, dict):
                row[key] = {name: _bounded_intel_value(endpoint[name]) for name in ("type", "id", "name")
                            if endpoint.get(name) is not None}
        for key in ("relationship_type", "type", "origin", "inferred"):
            if relation.get(key) is not None:
                row[key] = _bounded_intel_value(relation[key])
        evidence = relation.get("evidence", relation.get("description"))
        if evidence is not None:
            row["evidence"] = _bounded_intel_value(evidence)
        references = _source_urls({}, [relation])[:3]
        if references:
            row["source_references"] = references
        bounded.append(row)
    return bounded


def _intelligence_citations(records: list[dict[str, Any]], *, relationship_limit: int) -> list[dict[str, Any]]:
    citations: list[dict[str, Any]] = []
    for record in records:
        record_type = str(record.get("record_type") or "")
        record_id = str(record.get("record_id") or "")
        if not record_type or not record_id:
            continue
        relationships = _bounded_relationships(
            [item for item in record.get("relationships", []) if isinstance(item, dict)], relationship_limit,
        )
        references = _source_urls(record, relationships)
        details = {
            "record_type": record_type,
            "record_id": record_id,
            "name": record.get("name") or record.get("title"),
            "description": str(record.get("description") or "")[:1600],
            "severity": record.get("severity"),
            "published_date": record.get("published_date"),
            "tactics": _bounded_intel_value(record.get("tactics")),
            "platforms": _bounded_intel_value(record.get("platforms")),
            "affected_products": _bounded_intel_value(record.get("affected_products")),
            "technique_ids": _bounded_intel_value(record.get("technique_ids")),
            "technique_refs": _bounded_intel_value(record.get("technique_refs")),
            "rule_status": record.get("status"),
            "rule_level": record.get("level"),
            "relationships": relationships,
            "source_references": references,
        }
        # Avoid sending empty fields or full Sigma rule bodies to Gemini.
        details = {key: value for key, value in details.items() if value not in (None, "", [], {})}
        summary = json.dumps(details, ensure_ascii=False, default=str, separators=(",", ":"))[:3000]
        title = str(record.get("title") or record.get("name") or record_id)[:200]
        citations.append({
            "citation_id": f"I{len(citations) + 1}",
            "document_id": f"intelligence:{record_type}:{record_id}",
            "title": title,
            "source": references[0] if references else f"Intelligence record {record_type}:{record_id}",
            "page_number": None,
            "chunk_index": None,
            "excerpt": summary,
            "relevance_score": float(record.get("score") or 0.0),
            "source_type": "intelligence",
            "record_type": record_type,
            "record_id": record_id,
            "source_references": references,
            "relationships": relationships,
        })
    return citations


def _retrieve_intelligence(db: Database, *, org_id: str, tenant_id: str, question: str,
                           retriever: Callable[..., Any], relationship_retriever: Callable[..., Any],
                           top_k: int, relationship_limit: int) -> list[dict[str, Any]]:
    result = retriever(db, org_id=org_id, tenant_id=tenant_id, query=question,
                       page=1, page_size=top_k)
    if isinstance(result, dict):
        records = result.get("items", [])
    elif isinstance(result, list):
        records = result
    else:
        records = []
    enriched = []
    for record in records[:top_k]:
        if not isinstance(record, dict):
            continue
        row = dict(record)
        try:
            related = relationship_retriever(
                db, org_id=org_id, tenant_id=tenant_id,
                record_type=str(row.get("record_type") or ""),
                record_id=str(row.get("record_id") or ""), page=1,
                page_size=relationship_limit,
            )
            row["relationships"] = related.get("items", []) if isinstance(related, dict) else []
        except Exception:
            # A record remains useful even when its optional relationship lookup fails.
            logger.exception("Unable to retrieve relationships for intelligence record")
            row["relationships"] = []
        enriched.append(row)
    return enriched


async def generate_chat_turn(
    db: Database, *, org_id: str, tenant_id: str, user_id: str | None = None, question: str,
    history: list[dict[str, Any]], use_rag: bool = True,
    include_scanner: bool = False, provider: LLMProvider | None = None,
    retriever: Callable[..., list[dict[str, Any]]] | None = None,
    intelligence_retriever: Callable[..., Any] | None = None,
    relationship_retriever: Callable[..., Any] | None = None,
    language: str = "en",
) -> ChatTurn:
    active_provider = provider or get_provider()
    rag_enabled = bool(use_rag and config.CHAT_RAG_ENABLED)
    citations: list[dict[str, Any]] = []
    rag_status = "disabled"
    if rag_enabled:
        rag_status = "empty"
        retrieval = retriever or search_documents
        try:
            results = await asyncio.to_thread(
                retrieval, db, org_id=org_id, tenant_id=tenant_id,
                query=question, top_k=config.CHAT_RAG_TOP_K,
            )
            citations = _select_citations(results)
            rag_status = "available" if citations else "empty"
        except Exception:
            logger.exception("Knowledge retrieval failed; continuing without retrieved documents")
            rag_status = "unavailable"

    intelligence_status = "disabled"
    if config.CHAT_INTELLIGENCE_ENABLED:
        intelligence_status = "empty"
        try:
            records = await asyncio.to_thread(
                _retrieve_intelligence, db, org_id=org_id, tenant_id=tenant_id,
                question=question, retriever=intelligence_retriever or search_intelligence,
                relationship_retriever=relationship_retriever or list_relationships,
                top_k=config.CHAT_INTELLIGENCE_TOP_K,
                relationship_limit=config.CHAT_INTELLIGENCE_RELATIONSHIP_LIMIT,
            )
            intel_citations = _intelligence_citations(
                records, relationship_limit=config.CHAT_INTELLIGENCE_RELATIONSHIP_LIMIT,
            )
            citations.extend(intel_citations)
            intelligence_status = "available" if intel_citations else "empty"
        except Exception:
            logger.exception("Threat intelligence retrieval failed; continuing without it")
            intelligence_status = "unavailable"

    use_scanner = scanner_context_requested(question, explicit=include_scanner)
    scanner_sources = []
    if use_scanner:
        try:
            scanner_sources = await asyncio.to_thread(
                load_scanner_evidence, db, org_id=org_id, tenant_id=tenant_id, user_id=user_id,
            )
        except Exception:
            logger.exception("Scanner context retrieval failed; continuing without scanner records")
    messages, included_citations, included_scanner = build_prompt(
        question=question, history=history, citations=citations, scanner_sources=scanner_sources,
        max_context_chars=config.AI_CONTEXT_MAX_CHARS, history_window=config.AI_HISTORY_WINDOW,
        rag_requested=rag_enabled, scanner_requested=use_scanner,
        intelligence_requested=config.CHAT_INTELLIGENCE_ENABLED,
        intelligence_status=intelligence_status,
        rag_status=rag_status,
        language=language,
    )
    result = await active_provider.generate(messages)
    if not isinstance(result.content, str) or not result.content.strip():
        raise ProviderError("invalid_provider_response", "The configured AI provider returned an invalid answer.")
    allowed_urls = {url for source in included_citations for url in source.get("source_references", [])}
    allowed_urls.update(source.get("source") for source in included_citations
                        if str(source.get("source", "")).startswith(("https://", "http://")))
    answer = remove_unknown_citation_tags(
        result.content.strip()[:20000], {source["citation_id"] for source in included_citations}, allowed_urls,
    )
    grounded_intel_text = json.dumps(
        {"intelligence": included_citations, "endpoint_scanner_evidence": included_scanner},
        ensure_ascii=False, default=str,
    ).upper()
    grounded_intel_ids = set(_INTELLIGENCE_IDENTIFIER.findall(grounded_intel_text))
    unsupported_answer_ids = set(_INTELLIGENCE_IDENTIFIER.findall(answer.upper())) - grounded_intel_ids
    if unsupported_answer_ids:
        ids = ", ".join(sorted(unsupported_answer_ids))
        answer = (f"I couldn't verify {ids} in the retrieved sources, so I removed those unsupported details. "
                  "I won't guess; search again after adding a trusted source record.") if language != "hi" else (
                  f"प्राप्त स्रोतों में {ids} की पुष्टि नहीं हुई, इसलिए असमर्थित विवरण हटा दिए। "
                  "मैं अनुमान नहीं लगाऊँगा; विश्वसनीय स्रोत रिकॉर्ड जोड़ने के बाद फिर खोजें।")
    kb_citations = [item for item in included_citations if item.get("source_type") != "intelligence"]
    intel_citations = [item for item in included_citations if item.get("source_type") == "intelligence"]
    if rag_enabled and not kb_citations:
        if intel_citations:
            no_source = ("ज्ञान आधार से स्रोत नहीं मिला। threat-intelligence रिकॉर्ड अलग से उद्धृत हैं: " if language == "hi"
                         else "No relevant knowledge-base source was retrieved. Threat-intelligence records are cited separately: ")
        else:
            no_source = ("ज्ञान आधार से कोई संबंधित स्रोत नहीं मिला। सामान्य मार्गदर्शन: " if language == "hi"
                         else "No relevant knowledge-base source was retrieved. General guidance: ")
        answer = no_source + answer
    requested_ids = {value.upper() for value in _INTELLIGENCE_IDENTIFIER.findall(question)}
    available_intel_text = (" ".join(json.dumps(item, ensure_ascii=False, default=str) for item in intel_citations)
                            + json.dumps(included_scanner, ensure_ascii=False, default=str)).upper()
    missing_requested_ids = requested_ids - set(_INTELLIGENCE_IDENTIFIER.findall(available_intel_text))
    if config.CHAT_INTELLIGENCE_ENABLED and not intel_citations:
        if kb_citations and language != "hi":
            if intelligence_status == "unavailable":
                prefix = "Threat-intelligence retrieval is unavailable. Knowledge-base evidence is cited where relevant: "
            else:
                prefix = "No relevant tenant threat-intelligence record was retrieved. Knowledge-base evidence is cited where relevant: "
            answer = prefix + answer
        elif language == "hi":
            answer = "इस प्रश्न के लिए कोई संबंधित threat-intelligence रिकॉर्ड प्राप्त नहीं हुआ। नीचे सामान्य मार्गदर्शन है: " + answer
        elif intelligence_status == "unavailable":
            answer = "Threat-intelligence retrieval is currently unavailable. General guidance only: " + answer
        else:
            answer = "No relevant tenant threat-intelligence record was retrieved. General guidance only: " + answer
    if missing_requested_ids:
        ids = ", ".join(sorted(missing_requested_ids))
        if intelligence_status == "unavailable":
            answer = (f"Threat-intelligence retrieval is unavailable, so I couldn't verify {ids} and won't guess its details. "
                      "Retry when the intelligence service is available.") if language != "hi" else (
                      f"Threat-intelligence retrieval उपलब्ध नहीं है, इसलिए {ids} की पुष्टि नहीं कर सकता और विवरण का अनुमान नहीं लगाऊँगा। "
                      "सेवा उपलब्ध होने पर फिर से प्रयास करें।")
        elif intelligence_status == "disabled":
            answer = (f"Threat-intelligence lookup is disabled, so I couldn't verify {ids} and won't guess its details.") if language != "hi" else (
                      f"Threat-intelligence lookup बंद है, इसलिए {ids} की पुष्टि नहीं कर सकता और विवरण का अनुमान नहीं लगाऊँगा।")
        else:
            answer = (f"I couldn't retrieve a matching tenant intelligence record for {ids}, so I can't verify its details and won't guess. "
                      "Check the identifier or import a trusted source record before relying on specific claims.") if language != "hi" else (
                      f"{ids} के लिए tenant intelligence रिकॉर्ड नहीं मिला, इसलिए उसके विवरण की पुष्टि नहीं कर सकता और अनुमान नहीं लगाऊँगा। "
                      "विशिष्ट दावों पर भरोसा करने से पहले पहचान संख्या जाँचें या विश्वसनीय स्रोत रिकॉर्ड जोड़ें।")
    return ChatTurn(
        answer=answer, citations=included_citations, scanner_sources=included_scanner,
        provider=active_provider.provider_name, model=active_provider.model_name,
        token_usage=result.token_usage, rag_enabled=rag_enabled,
    )


async def generate_detailed_explanation(
    *, question: str, answer: str, citations: list[dict[str, Any]],
    scanner_sources: list[dict[str, Any]], language: str = "en",
    provider: LLMProvider | None = None,
) -> str:
    """Expand a saved answer using only the evidence attached to that answer."""
    active_provider = provider or get_provider()
    required = ["Threat overview", "Threat classification", "Reason for detection",
                "Evidence from the actual scan", "Potential system impact", "Step-by-step remediation",
                "Prevention recommendations", "Relevant technical indicators", "Confidence level and explanation"]
    if language == "hi":
        required = ["खतरे का परिचय", "खतरे का वर्गीकरण", "पहचान का कारण", "वास्तविक scan के सबूत",
                    "सिस्टम पर संभावित असर", "सुधार के चरण", "बचाव के सुझाव", "तकनीकी संकेतक",
                    "विश्वास स्तर और उसका कारण"]
        lang = "Respond entirely in Hindi using Devanagari. Preserve malware, IP address, process ID, hash, CVE, code, file paths, hashes and identifiers exactly."
    else:
        lang = "Respond entirely in English."
    evidence = {"citations": citations, "scanner_sources": scanner_sources}
    messages = [
        {"role": "system", "content": SECURITY_ANALYST_SYSTEM_PROMPT + "\n" + lang +
         "\nProvide a detailed explanation with these nine sections, using the supplied heading equivalents in order: " +
         "; ".join(required) + ". Use only evidence in the user message. Explicitly say when data is missing; do not infer a confidence score. Keep evidence and advice distinct."},
        {"role": "user", "content": json.dumps(
            {"question": question, "short_answer": answer, "available_evidence": evidence},
            ensure_ascii=False, default=str, separators=(",", ":"),
        )},
    ]
    result = await active_provider.generate(messages)
    if not isinstance(result.content, str) or not result.content.strip():
        raise ProviderError("invalid_provider_response", "The configured AI provider returned an invalid explanation.")
    allowed_urls = {url for citation in citations for url in citation.get("source_references", [])}
    allowed_urls.update(citation.get("source") for citation in citations
                        if str(citation.get("source", "")).startswith(("https://", "http://")))
    labels = {str(citation.get("citation_id")) for citation in citations if citation.get("citation_id")}
    return remove_unknown_citation_tags(result.content.strip()[:30000], labels, allowed_urls)
