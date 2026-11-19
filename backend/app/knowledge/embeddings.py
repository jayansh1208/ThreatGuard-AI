from __future__ import annotations

import logging
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Sequence

import numpy as np

from backend.app.config import EMBEDDING_CACHE_DIR, EMBEDDING_DEVICE, EMBEDDING_MODEL, EMBEDDING_PROVIDER

logger = logging.getLogger(__name__)


class EmbeddingProvider(ABC):
    """Provider contract consumed by ingestion and retrieval, independent of storage."""

    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @property
    @abstractmethod
    def dimension(self) -> int: ...

    @abstractmethod
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class SentenceTransformerProvider(EmbeddingProvider):
    def __init__(self, model_name: str = EMBEDDING_MODEL, device: str = EMBEDDING_DEVICE,
                 cache_dir: str = EMBEDDING_CACHE_DIR):
        # This provider is PyTorch based; avoid loading an unrelated TensorFlow/Keras stack.
        os.environ["USE_TF"] = "0"
        from sentence_transformers import SentenceTransformer
        import torch

        if device.startswith("cuda") and not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested for embeddings, but CUDA is not available.")
        cache_path = Path(cache_dir).expanduser()
        if not cache_path.is_absolute():
            cache_path = Path(__file__).resolve().parents[3] / cache_path
        cache_path.mkdir(parents=True, exist_ok=True)
        self._model_name = model_name
        logger.info("Loading sentence-transformer model=%s device=%s cache_dir=%s",
                    model_name, device, cache_path)
        try:
            self._model = SentenceTransformer(model_name, device=device, cache_folder=str(cache_path))
        except Exception:
            logger.exception("Sentence-transformer initialization failed (model=%s, device=%s, torch=%s)",
                             model_name, device, torch.__version__)
            raise
        self._dimension = int(self._model.get_sentence_embedding_dimension())
        if self._dimension <= 0:
            raise RuntimeError("Embedding model returned an invalid vector dimension.")
        self._encode_lock = threading.Lock()
        logger.info("Sentence-transformer ready (model=%s, dimension=%d, device=%s)",
                    self._model_name, self._dimension, device)

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        # SentenceTransformer encode is shared by all request threads. Serialize access
        # so model state and its internal tokenization/inference buffers stay safe.
        with self._encode_lock:
            vectors = np.asarray(self._model.encode(
                list(texts), convert_to_numpy=True, show_progress_bar=False, batch_size=32,
            ), dtype=np.float32)
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)
        if vectors.shape[1] != self.dimension:
            raise RuntimeError(f"Embedding dimension changed: expected {self.dimension}, got {vectors.shape[1]}.")
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        if np.any(norms == 0):
            raise RuntimeError("Embedding model returned a zero vector.")
        normalized = vectors / norms
        return normalized.astype(np.float32, copy=False).tolist()


def get_embedding_provider() -> EmbeddingProvider:
    """Return the process-wide provider, loading it once even on concurrent first use."""
    global _provider
    if EMBEDDING_PROVIDER != "sentence_transformers":
        raise ValueError(f"Unsupported embedding provider: {EMBEDDING_PROVIDER}")
    if _provider is not None:
        return _provider
    with _provider_lock:
        if _provider is None:
            logger.info("Initializing embedding provider=%s model=%s device=%s",
                        EMBEDDING_PROVIDER, EMBEDDING_MODEL, EMBEDDING_DEVICE)
            # A failed initialization is deliberately not cached; a later request can retry.
            _provider = SentenceTransformerProvider()
    return _provider


_provider: EmbeddingProvider | None = None
_provider_lock = threading.Lock()
