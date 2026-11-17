from __future__ import annotations

import asyncio

from backend.app import config
from backend.app.ai.chat_service import generate_chat_turn
from backend.app.ai.providers.base import LLMProvider, LLMResult
from backend.app.ai.providers.gemini_provider import GeminiProvider
from backend.app.intelligence.search import search_intelligence


SOURCE_URL = "https://nvd.nist.gov/vuln/detail/CVE-2025-1234"


class FakeResponse:
    status_code = 200

    def json(self):
        return {
            "candidates": [{"content": {"parts": [{
                "text": "CVE-2025-1234 is recorded as high severity [I1]. "
                        "More details: https://invented.invalid/detail [I99]"
            }]}}],
            "usageMetadata": {"promptTokenCount": 30, "candidatesTokenCount": 15},
        }


class FakeAsyncClient:
    last_request = None

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def post(self, url, **kwargs):
        type(self).last_request = {"url": url, **kwargs}
        return FakeResponse()


class FakeLLM(LLMProvider):
    def __init__(self, content="A general defensive answer."):
        self.content = content
        self.messages = None

    @property
    def provider_name(self):
        return "mock-gemini"

    @property
    def model_name(self):
        return "mock-model"

    async def generate(self, messages):
        self.messages = messages
        return LLMResult(self.content, {"total_tokens": 8})


class FakeCursor(list):
    def batch_size(self, _size):
        return self


class FakeIntelligenceCollection:
    def __init__(self, records):
        self.records = records

    def find_one(self, query, _projection=None):
        return next((dict(row) for row in self.records
                     if all(row.get(key) == value for key, value in query.items())), None)

    def find(self, query, _projection=None):
        return FakeCursor([dict(row) for row in self.records
                           if all(row.get(key) == value for key, value in query.items())])


class FakeEmbeddingProvider:
    model_name = "phase5-test-embedding"
    dimension = 2

    def embed(self, texts):
        return [[1.0, 0.0] for _ in texts]


class FakeMongo:
    def __init__(self):
        self.collections = {
            "vulnerabilities": FakeIntelligenceCollection([
                {"org_id": "org-a", "tenant_id": "tenant-a", "cve_id": "CVE-2025-1111",
                 "description": "Tenant A vulnerability record", "severity": "high"},
                {"org_id": "org-a", "tenant_id": "tenant-b", "cve_id": "CVE-2025-2222",
                 "description": "Tenant B secret vulnerability record", "severity": "critical"},
            ]),
            "attack_techniques": FakeIntelligenceCollection([]),
            "attack_patterns": FakeIntelligenceCollection([]),
            "detection_rules": FakeIntelligenceCollection([]),
        }

    def __getitem__(self, key):
        return self.collections[key]


def intel_result(record_id="CVE-2025-1234"):
    return {"items": [{
        "record_type": "cve", "record_id": record_id, "record_kind": "vulnerability",
        "title": "CVE-2025-1234", "description": "A test vulnerability description.",
        "severity": "high", "references": [SOURCE_URL], "score": 0.91,
    }], "total": 1, "page": 1, "page_size": 5}


def test_gemini_receives_structured_intelligence_and_citations_are_source_bounded(monkeypatch):
    from backend.app.ai.providers import gemini_provider

    monkeypatch.setattr(config, "GEMINI_API_KEY", "mock-api-key")
    monkeypatch.setattr(config, "GEMINI_MODEL", "gemini-mock")
    monkeypatch.setattr(gemini_provider.httpx, "AsyncClient", FakeAsyncClient)
    scopes = []

    def retrieve(_db, **kwargs):
        scopes.append((kwargs["org_id"], kwargs["tenant_id"]))
        return intel_result()

    def relationships(_db, **kwargs):
        assert kwargs["record_type"] == "cve"
        assert kwargs["record_id"] == "CVE-2025-1234"
        return {"items": [{
            "relationship_type": "associated_with", "origin": "inferred", "inferred": True,
            "evidence": "Analyst documented an association; not a confirmed fact.",
            "source_references": ["https://example.test/report"],
        }]}

    turn = asyncio.run(generate_chat_turn(
        object(), org_id="org-a", tenant_id="tenant-a", question="Explain CVE-2025-1234",
        history=[], use_rag=False, provider=GeminiProvider(),
        intelligence_retriever=retrieve, relationship_retriever=relationships,
    ))

    assert scopes == [("org-a", "tenant-a")]
    assert turn.provider == "gemini"
    assert turn.citations[0]["citation_id"] == "I1"
    assert turn.citations[0]["record_id"] == "CVE-2025-1234"
    assert turn.citations[0]["source_references"] == [SOURCE_URL, "https://example.test/report"]
    assert turn.citations[0]["relationships"][0]["origin"] == "inferred"
    assert "[I1]" in turn.answer
    assert "[I99]" not in turn.answer
    assert "invented.invalid" not in turn.answer
    sent = FakeAsyncClient.last_request["json"]
    user_content = "\n".join(part["text"] for item in sent["contents"] for part in item["parts"])
    assert "CVE-2025-1234" in user_content
    assert "official-source" not in user_content  # The association is explicitly inferred.
    assert "not a confirmed fact" in user_content
    assert "never fill missing records" in sent["systemInstruction"]["parts"][0]["text"].lower()


def test_unavailable_intelligence_keeps_chat_useful_and_preserves_knowledge_rag():
    llm = FakeLLM("The source recommends enabling MFA.")

    def unavailable_intel(*_args, **_kwargs):
        raise RuntimeError("mock intelligence collection unavailable")

    turn = asyncio.run(generate_chat_turn(
        object(), org_id="org-a", tenant_id="tenant-a", question="How can I secure accounts?",
        history=[], use_rag=True, provider=llm,
        retriever=lambda *_args, **_kwargs: [{
            "document_id": "doc-a", "filename": "account-guide.md", "source": "account-guide.md",
            "excerpt": "Enable multifactor authentication.", "relevance_score": 0.9,
        }],
        intelligence_retriever=unavailable_intel,
    ))

    assert turn.answer.startswith("Threat-intelligence retrieval is unavailable. Knowledge-base evidence is cited where relevant:")
    assert turn.citations[0]["document_id"] == "doc-a"
    assert "Knowledge-base retrieval was unavailable" not in llm.messages[-1]["content"]
    assert "Threat-intelligence retrieval was unavailable" in llm.messages[-1]["content"]
    assert "account-guide.md" in llm.messages[-1]["content"]


def test_empty_intelligence_says_no_matching_records_without_inventing_specifics():
    llm = FakeLLM("CVE-2020-9999 is a critical RCE vulnerability [I1].")
    turn = asyncio.run(generate_chat_turn(
        object(), org_id="org-a", tenant_id="tenant-a", question="What is CVE-2020-9999?",
        history=[], use_rag=False, provider=llm,
        intelligence_retriever=lambda *_args, **_kwargs: {"items": [], "total": 0},
    ))
    assert "couldn't retrieve a matching tenant intelligence record for CVE-2020-9999" in turn.answer
    assert "critical RCE" not in turn.answer
    assert "[I1]" not in turn.answer
    assert "Do not invent CVEs" in llm.messages[-1]["content"]


def test_unavailable_intelligence_does_not_claim_the_requested_record_is_absent():
    llm = FakeLLM("CVE-2025-1234 is a critical vulnerability.")

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("mock outage")

    turn = asyncio.run(generate_chat_turn(
        object(), org_id="org-a", tenant_id="tenant-a", question="Explain CVE-2025-1234",
        history=[], use_rag=False, provider=llm, intelligence_retriever=unavailable,
    ))
    assert "retrieval is unavailable" in turn.answer
    assert "couldn't verify CVE-2025-1234" in turn.answer
    assert "no matching tenant intelligence record" not in turn.answer


def test_empty_intelligence_still_allows_labeled_general_guidance():
    llm = FakeLLM("Use MFA and review account recovery options.")
    turn = asyncio.run(generate_chat_turn(
        object(), org_id="org-a", tenant_id="tenant-a", question="How can I protect my account?",
        history=[], use_rag=False, provider=llm,
        intelligence_retriever=lambda *_args, **_kwargs: {"items": [], "total": 0},
    ))
    assert turn.answer.startswith("No relevant tenant threat-intelligence record was retrieved. General guidance only:")
    assert "Use MFA" in turn.answer
    assert turn.citations == []


def test_chat_removes_unverified_identifiers_in_generated_answers():
    llm = FakeLLM("CVE-2025-8888 is a critical remote-code-execution flaw.")
    turn = asyncio.run(generate_chat_turn(
        object(), org_id="org-a", tenant_id="tenant-a", question="Tell me about recent threats",
        history=[], use_rag=False, provider=llm,
        intelligence_retriever=lambda *_args, **_kwargs: {"items": [], "total": 0},
    ))
    assert "couldn't verify CVE-2025-8888" in turn.answer
    assert "critical remote-code-execution flaw" not in turn.answer


def test_chat_intelligence_search_never_includes_another_tenant_record():
    db = FakeMongo()
    llm = FakeLLM("The source describes a vulnerability [I1].")

    def retrieve(database, **kwargs):
        return search_intelligence(database, **kwargs, provider=FakeEmbeddingProvider())

    turn = asyncio.run(generate_chat_turn(
        db, org_id="org-a", tenant_id="tenant-a", question="Find vulnerability records",
        history=[], use_rag=False, provider=llm, intelligence_retriever=retrieve,
        relationship_retriever=lambda *_args, **_kwargs: {"items": []},
    ))

    assert [item["record_id"] for item in turn.citations] == ["CVE-2025-1111"]
    assert "Tenant B secret" not in repr(turn.citations)
    assert "CVE-2025-2222" not in llm.messages[-1]["content"]


def test_empty_intelligence_store_does_not_initialize_or_call_embeddings():
    class EmptyMongo:
        def __getitem__(self, _key):
            return FakeIntelligenceCollection([])

    class MustNotEmbed:
        def embed(self, _texts):
            raise AssertionError("Empty intelligence should not spend time loading embeddings")

    result = search_intelligence(EmptyMongo(), org_id="org-a", tenant_id="tenant-a",
                                 query="CVE-2025-1234", provider=MustNotEmbed())
    assert result["items"] == []
    assert result["total"] == 0
