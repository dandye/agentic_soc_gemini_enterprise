"""In-Process GLiNER2.5-Decide Operational Decision Engine.

Loads and executes fastino/GLiNER2.5-Decide directly in memory (CPU or GPU)
for zero-shot multi-head decision classification across SOC triage, routing, and gates.
"""

import logging
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "fastino/GLiNER2.5-Decide"


class GLiNERDecideEngine:
  """Thread-safe, lazy-loading in-process GLiNER2.5-Decide engine."""

  _instance: Optional["GLiNERDecideEngine"] = None
  _lock = threading.Lock()

  def __init__(self, model_id: str = DEFAULT_MODEL_ID):
    self.model_id = model_id
    self._model = None
    self._is_loaded = False
    self._load_lock = threading.Lock()

  @classmethod
  def get_instance(
      cls, model_id: str = DEFAULT_MODEL_ID
  ) -> "GLiNERDecideEngine":
    """Singleton accessor ensuring a single model instance in process memory."""
    if cls._instance is None:
      with cls._lock:
        if cls._instance is None:
          cls._instance = cls(model_id=model_id)
    return cls._instance

  @property
  def is_loaded(self) -> bool:
    """Returns True if model weights are loaded in memory."""
    return self._is_loaded

  def _ensure_loaded(self) -> None:
    """Lazy-loads the model weights into memory on first execution."""
    if self._is_loaded:
      return

    with self._load_lock:
      if self._is_loaded:
        return

      logger.info(
          "Initializing GLiNER2.5-Decide engine with model: %s", self.model_id
      )
      try:
        import torch
        from gliner2 import AutoExtractor

        device = "cuda" if torch.cuda.is_available() else "cpu"
        self._model = AutoExtractor.from_pretrained(
            self.model_id, map_location=device
        )
        self._is_loaded = True
        logger.info("GLiNER2.5-Decide model successfully loaded on %s", device)
      except Exception as e:
        logger.error("Failed to load GLiNER2.5-Decide model: %s", e)
        raise RuntimeError(
            f"Failed to load GLiNER2.5-Decide ({self.model_id}): {e}"
        ) from e

  def decide(
      self, text: str, schema: Dict[str, Any], **kwargs
  ) -> Dict[str, Any]:
    """Classifies input text against a multi-head schema in a single forward pass.

    Args:
        text: Input text string (alert, ticket, summary, or report).
        schema: Decision schema mapping head names to lists of candidate
          labels.
        **kwargs: Additional parameters passed to `classify_text`.

    Returns:
        Dictionary mapping head names to predicted labels or scores.
    """
    if not text or not text.strip():
      return {}

    self._ensure_loaded()
    return self._model.classify_text(text.strip(), schema, **kwargs)
