from __future__ import annotations

import asyncio
import json
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


async def generate_chat_turn(
    db: Database, *, org_id: str, tenant_id: str, question: str,
    history: list[dict[str, Any]], use_rag: bool = True,
    include_scanner: bool = False, provider: LLMProvider | None = None,
    retriever: Callable[..., list[dict[str, Any]]] | None = None,
    language: str = "en",
) -> ChatTurn:
    active_provider = provider or get_provider()
    rag_enabled = bool(use_rag and config.CHAT_RAG_ENABLED)
    citations: list[dict[str, Any]] = []
    if rag_enabled:
        retrieval = retriever or search_documents
        try:
            results = await asyncio.to_thread(
                retrieval, db, org_id=org_id, tenant_id=tenant_id,
                query=question, top_k=config.CHAT_RAG_TOP_K,
            )
        except Exception as exc:
            raise ProviderError("rag_unavailable", "Knowledge retrieval failed; no answer was generated.") from exc
        citations = _select_citations(results)

    use_scanner = scanner_context_requested(question, explicit=include_scanner)
    scanner_sources = await asyncio.to_thread(
        load_scanner_evidence, db, org_id=org_id, tenant_id=tenant_id,
    ) if use_scanner else []
    messages, included_citations, included_scanner = build_prompt(
        question=question, history=history, citations=citations, scanner_sources=scanner_sources,
        max_context_chars=config.AI_CONTEXT_MAX_CHARS, history_window=config.AI_HISTORY_WINDOW,
        rag_requested=rag_enabled, scanner_requested=use_scanner,
        language=language,
    )
    result = await active_provider.generate(messages)
    if not isinstance(result.content, str) or not result.content.strip():
        raise ProviderError("invalid_provider_response", "The configured AI provider returned an invalid answer.")
    answer = remove_unknown_citation_tags(
        result.content.strip()[:20000], {source["citation_id"] for source in included_citations},
    )
    if rag_enabled and not included_citations:
        no_source = ("ज्ञान आधार से कोई संबंधित स्रोत नहीं मिला। सामान्य मार्गदर्शन: " if language == "hi"
                     else "No relevant knowledge-base source was retrieved. General guidance: ")
        answer = no_source + answer
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
    return result.content.strip()[:30000]
