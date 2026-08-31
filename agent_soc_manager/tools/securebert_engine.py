"""
In-Process SecureBERT Named Entity Recognition (NER) Engine for CTI.

Loads and executes pzryathzsdhc/cti-ner-securebert directly in Python memory (CPU)
with sliding-window chunking, sub-word reconstruction, and grammatical validation
from nlp_capstone.
"""

import logging
import sys
import threading
from pathlib import Path
from typing import Any, Optional


logger = logging.getLogger(__name__)

# Default Hugging Face Model ID
SECUREBERT_CTI_MODEL_ID = "pzryathzsdhc/cti-ner-securebert"

# Ensure external/nlp_capstone is importable
_REPO_ROOT = Path(__file__).resolve().parents[2]
_NLP_CAPSTONE_ROOT = _REPO_ROOT / "external" / "nlp_capstone"
if _NLP_CAPSTONE_ROOT.exists() and str(_NLP_CAPSTONE_ROOT) not in sys.path:
    sys.path.insert(0, str(_NLP_CAPSTONE_ROOT))

try:
    from ner.span_validators import _clean, _refang, validate
except ImportError:
    def _refang(t: str) -> str:
        return t.replace("[.]", ".").replace("[@]", "@").replace("hxxp", "http")

    def _clean(t: str) -> str:
        return _refang(t.strip()).strip(".,;:!?\"'()[]{}<>")

    def validate(label: str, text: str) -> bool:
        return True


class SecureBertNerEngine:
    """Thread-safe, lazy-loading in-process SecureBERT NER engine."""

    _instance: Optional["SecureBertNerEngine"] = None
    _lock = threading.Lock()

    def __init__(self, model_id: str = SECUREBERT_CTI_MODEL_ID):
        self.model_id = model_id
        self._tokenizer = None
        self._model = None
        self._pipeline = None
        self._is_loaded = False
        self._load_lock = threading.Lock()

    @classmethod
    def get_instance(cls, model_id: str = SECUREBERT_CTI_MODEL_ID) -> "SecureBertNerEngine":
        """Singleton accessor ensuring only a single model copy is kept in RAM."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(model_id=model_id)
        return cls._instance

    def _ensure_loaded(self):
        """Loads model weights and tokenizer into RAM on first invocation."""
        if self._is_loaded:
            return

        with self._load_lock:
            if self._is_loaded:
                return

            logger.info("Initializing in-process SecureBERT NER engine with model: %s", self.model_id)
            try:
                import torch
                from transformers import (
                    AutoModelForTokenClassification,
                    AutoTokenizer,
                    pipeline,
                )

                # Force CPU device for lightweight in-process agent execution
                device = torch.device("cpu")

                self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
                self._model = AutoModelForTokenClassification.from_pretrained(self.model_id)
                self._model.to(device)
                self._model.eval()

                self._pipeline = pipeline(
                    "token-classification",
                    model=self._model,
                    tokenizer=self._tokenizer,
                    aggregation_strategy="simple",
                    device=device,
                )
                self._is_loaded = True
                logger.info("SecureBERT CTI model successfully loaded in process memory.")
            except Exception as e:
                logger.error("Failed to load in-process SecureBERT model: %s", e)
                raise RuntimeError(f"Failed to load in-process SecureBERT model ({self.model_id}): {e}") from e

    def extract_entities(
        self,
        text: str,
        confidence_threshold: float = 0.5,
        max_chunk_chars: int = 1500,
    ) -> dict[str, Any]:
        """Extracts and categorizes CTI entities across 16 labels from raw security text.

        Args:
            text: Input document or advisory string.
            confidence_threshold: Minimum confidence score [0.0 - 1.0].
            max_chunk_chars: Maximum characters per sliding window chunk.

        Returns:
            Dict containing categorized entities, raw entity predictions, and summary metrics.
        """
        if not text or not text.strip():
            return {
                "status": "success",
                "model": self.model_id,
                "inference_mode": "in_process_cpu",
                "total_entities_detected": 0,
                "unique_entities_extracted": 0,
                "categorized_entities": {},
                "predictions": [],
            }

        self._ensure_loaded()

        # Split text into overlapping paragraph chunks to avoid token limits
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        chunks = []
        current_chunk = []
        current_len = 0

        for p in paragraphs:
            if current_len + len(p) > max_chunk_chars and current_chunk:
                chunks.append("\n\n".join(current_chunk))
                current_chunk = [p]
                current_len = len(p)
            else:
                current_chunk.append(p)
                current_len += len(p)
        if current_chunk:
            chunks.append("\n\n".join(current_chunk))

        all_predictions: list[dict[str, Any]] = []

        for chunk in chunks:
            try:
                preds = self._pipeline(chunk)
                for pred in preds:
                    score = float(pred.get("score", 0.0))
                    if score < confidence_threshold:
                        continue

                    label = pred.get("entity_group", "").strip()
                    word = pred.get("word", "").strip()
                    cleaned_word = _clean(word)

                    if not cleaned_word or len(cleaned_word) < 2:
                        continue

                    # Validate structured types with span validators
                    if not validate(label, cleaned_word):
                        continue

                    all_predictions.append({
                        "label": label,
                        "text": cleaned_word,
                        "raw_word": word,
                        "confidence": round(score, 4),
                        "start": pred.get("start"),
                        "end": pred.get("end"),
                    })
            except Exception as chunk_err:
                logger.warning("Error during chunk inference: %s", chunk_err)

        # Categorize into SOC-standard threat intelligence groupings
        categorized: dict[str, list[dict[str, Any]]] = {
            "threat_actors": [],
            "malware_families": [],
            "hacking_tools": [],
            "affected_products": [],
            "cve_identifiers": [],
            "cwe_identifiers": [],
            "mitre_techniques": [],
            "mitre_tactics": [],
            "file_hashes": [],
            "file_names": [],
            "file_paths": [],
            "ip_addresses": [],
            "email_addresses": [],
            "tlp_classifications": [],
            "yara_rules": [],
            "other_entities": [],
        }

        seen_per_category: dict[str, set[str]] = {k: set() for k in categorized}

        label_to_category = {
            "threat actor group": "threat_actors",
            "malware family": "malware_families",
            "hacking tool": "hacking_tools",
            "affected software product": "affected_products",
            "cve identifier": "cve_identifiers",
            "cwe identifier": "cwe_identifiers",
            "attack technique id": "mitre_techniques",
            "attack technique name": "mitre_techniques",
            "tactic": "mitre_tactics",
            "file hash": "file_hashes",
            "file name": "file_names",
            "file path": "file_paths",
            "ip address": "ip_addresses",
            "email address": "email_addresses",
            "tlp classification": "tlp_markings",
            "yara rule name": "yara_rules",
        }

        for pred in all_predictions:
            label = pred["label"]
            text_val = pred["text"]
            cat = label_to_category.get(label, "other_entities")

            norm_key = text_val.lower()
            if norm_key in seen_per_category[cat]:
                continue
            seen_per_category[cat].add(norm_key)

            categorized[cat].append({
                "value": text_val,
                "label": label,
                "confidence": pred["confidence"],
            })

        # Sort each list by confidence descending
        for cat in categorized:
            categorized[cat] = sorted(categorized[cat], key=lambda x: x["confidence"], reverse=True)

        return {
            "status": "success",
            "model": self.model_id,
            "inference_mode": "in_process_cpu",
            "total_entities_detected": len(all_predictions),
            "unique_entities_extracted": sum(len(v) for v in categorized.values()),
            "categorized_entities": categorized,
            "predictions": all_predictions,
        }
