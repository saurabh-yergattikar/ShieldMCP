"""DistilBERT-based binary classifier for MCP tool description safety.

Scores tool descriptions from 0.0 (benign) to 1.0 (contains embedded action
directives / tool poisoning). Designed to be fine-tuned on the Stage 1 training
dataset (8,400 benign + 3,200 adversarial descriptions).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "distilbert-base-uncased"
_MAX_LENGTH = 512
_LABEL_MALICIOUS = 1


class DescriptionClassifier:
    """Binary classifier for detecting adversarial tool descriptions.

    Uses a DistilBERT model fine-tuned for sequence classification.
    Label 0 = benign, Label 1 = malicious (contains action directives).
    """

    def __init__(self, model_path: str | None = None, device: str = "cpu") -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:
            raise ImportError(
                "The 'transformers' and 'torch' packages are required for the classifier. "
                "Install them with: pip install shieldmcp[ml]"
            ) from e

        self.device = device
        self._torch = torch

        source = model_path or _DEFAULT_MODEL
        logger.info("Loading classifier model from %s on %s", source, device)

        self.tokenizer = AutoTokenizer.from_pretrained(source)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            source, num_labels=2
        ).to(device)
        self.model.eval()
        self._is_fine_tuned = model_path is not None

    @property
    def is_fine_tuned(self) -> bool:
        return self._is_fine_tuned

    def predict(self, text: str) -> float:
        """Return a maliciousness score in [0.0, 1.0] for a single description."""
        return self.predict_batch([text])[0]

    def predict_batch(self, texts: list[str]) -> list[float]:
        """Return maliciousness scores for a batch of descriptions."""
        torch = self._torch

        inputs = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=_MAX_LENGTH,
            return_tensors="pt",
        ).to(self.device)

        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)
            scores = probs[:, _LABEL_MALICIOUS].cpu().tolist()

        return scores

    def load_model(self, path: str) -> None:
        """Load fine-tuned weights from disk."""
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        logger.info("Loading fine-tuned model from %s", path)
        self.tokenizer = AutoTokenizer.from_pretrained(path)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            path, num_labels=2
        ).to(self.device)
        self.model.eval()
        self._is_fine_tuned = True

    def save_model(self, path: str) -> None:
        """Save current model weights and tokenizer to disk."""
        out = Path(path)
        out.mkdir(parents=True, exist_ok=True)
        logger.info("Saving model to %s", out)
        self.model.save_pretrained(out)
        self.tokenizer.save_pretrained(out)
