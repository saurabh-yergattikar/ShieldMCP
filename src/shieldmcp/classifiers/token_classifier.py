"""Token-level classifier for detecting instructional content in MCP tool responses.

Tags each token as INFORMATIONAL (O) or INSTRUCTIONAL (B-INST / I-INST) using a
fine-tuned DistilBERT model with BIO tagging. Inspired by Das et al. (2025) for
identifying directive language segments in untrusted tool output.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "distilbert-base-uncased"
_MAX_LENGTH = 512
_LABEL_MAP = {0: "O", 1: "B-INST", 2: "I-INST"}
_ID_MAP = {"O": 0, "B-INST": 1, "I-INST": 2}
_NUM_LABELS = 3


class InstructionTokenClassifier:
    """Token-level classifier for detecting instructional spans in text.

    Uses BIO tagging: O = informational, B-INST = beginning of instruction,
    I-INST = inside instruction. Built on DistilBERT for token classification.
    """

    def __init__(self, model_path: str | None = None, device: str = "cpu") -> None:
        self._torch: Any = None
        self._model: Any = None
        self._tokenizer: Any = None
        self.device = device
        self._is_fine_tuned = model_path is not None

        try:
            import torch
            from transformers import AutoModelForTokenClassification, AutoTokenizer

            self._torch = torch

            source = model_path or _DEFAULT_MODEL
            logger.info("Loading token classifier from %s on %s", source, device)

            self._tokenizer = AutoTokenizer.from_pretrained(source)

            if model_path is not None:
                self._model = AutoModelForTokenClassification.from_pretrained(
                    source, num_labels=_NUM_LABELS
                ).to(device)
            else:
                self._model = AutoModelForTokenClassification.from_pretrained(
                    source, num_labels=_NUM_LABELS, ignore_mismatched_sizes=True
                ).to(device)
            self._model.eval()
            self._available = True
        except ImportError:
            logger.warning(
                "transformers/torch not installed — token classifier unavailable. "
                "Install with: pip install shieldmcp[ml]"
            )
            self._available = False
        except Exception:
            logger.exception("Failed to load token classifier model")
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    @property
    def is_fine_tuned(self) -> bool:
        return self._is_fine_tuned

    def predict(self, text: str) -> dict[str, Any]:
        """Classify tokens and return instruction score, spans, and ratio.

        Returns:
            {
                "score": float (0.0-1.0 overall instruction score),
                "instructional_spans": [{"text": str, "start": int, "end": int, "confidence": float}, ...],
                "instructional_ratio": float (fraction of tokens classified as instructional),
            }
        """
        if not self._available:
            return {"score": 0.0, "instructional_spans": [], "instructional_ratio": 0.0}

        results = self.predict_batch([text])
        return results[0]

    def predict_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Batch prediction over multiple texts."""
        if not self._available:
            return [
                {"score": 0.0, "instructional_spans": [], "instructional_ratio": 0.0}
                for _ in texts
            ]

        torch = self._torch
        results: list[dict[str, Any]] = []

        inputs = self._tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=_MAX_LENGTH,
            return_tensors="pt",
            return_offsets_mapping=True,
        ).to(self.device)

        offset_mapping = inputs.pop("offset_mapping").cpu().tolist()

        with torch.no_grad():
            logits = self._model(**inputs).logits
            probs = torch.softmax(logits, dim=-1).cpu()
            preds = torch.argmax(logits, dim=-1).cpu().tolist()

        for i, text in enumerate(texts):
            token_preds = preds[i]
            token_probs = probs[i]
            offsets = offset_mapping[i]
            input_ids = inputs["input_ids"][i].cpu().tolist()

            spans = self._extract_spans(
                text, token_preds, token_probs, offsets, input_ids
            )

            n_real_tokens = sum(
                1 for j, (start, end) in enumerate(offsets)
                if not (start == 0 and end == 0)
            )
            n_inst = sum(
                1 for j, (start, end) in enumerate(offsets)
                if not (start == 0 and end == 0) and token_preds[j] in (1, 2)
            )

            ratio = n_inst / max(n_real_tokens, 1)
            inst_probs = [
                token_probs[j][token_preds[j]].item()
                for j, (start, end) in enumerate(offsets)
                if not (start == 0 and end == 0) and token_preds[j] in (1, 2)
            ]
            avg_conf = sum(inst_probs) / max(len(inst_probs), 1) if inst_probs else 0.0
            score = min(1.0, ratio * 0.6 + avg_conf * 0.4) if n_inst > 0 else 0.0

            results.append({
                "score": round(score, 4),
                "instructional_spans": spans,
                "instructional_ratio": round(ratio, 4),
            })

        return results

    def _extract_spans(
        self,
        text: str,
        token_preds: list[int],
        token_probs: Any,
        offsets: list[list[int]],
        input_ids: list[int],
    ) -> list[dict[str, Any]]:
        """Convert BIO token predictions to character-level spans."""
        spans: list[dict[str, Any]] = []
        current_start: int | None = None
        current_end: int = 0
        current_confs: list[float] = []

        for j, (start, end) in enumerate(offsets):
            if start == 0 and end == 0:
                continue

            label = token_preds[j]
            conf = token_probs[j][label].item()

            if label == 1:  # B-INST
                if current_start is not None:
                    spans.append(self._make_span(text, current_start, current_end, current_confs))
                current_start = start
                current_end = end
                current_confs = [conf]
            elif label == 2 and current_start is not None:  # I-INST
                current_end = end
                current_confs.append(conf)
            else:  # O
                if current_start is not None:
                    spans.append(self._make_span(text, current_start, current_end, current_confs))
                    current_start = None
                    current_confs = []

        if current_start is not None:
            spans.append(self._make_span(text, current_start, current_end, current_confs))

        return spans

    @staticmethod
    def _make_span(
        text: str, start: int, end: int, confidences: list[float]
    ) -> dict[str, Any]:
        return {
            "text": text[start:end],
            "start": start,
            "end": end,
            "confidence": round(sum(confidences) / len(confidences), 4) if confidences else 0.0,
        }

    def load_model(self, path: str) -> None:
        """Load fine-tuned weights from disk."""
        if self._torch is None:
            raise RuntimeError("torch/transformers not available")

        from transformers import AutoModelForTokenClassification, AutoTokenizer

        logger.info("Loading fine-tuned token classifier from %s", path)
        self._tokenizer = AutoTokenizer.from_pretrained(path)
        self._model = AutoModelForTokenClassification.from_pretrained(
            path, num_labels=_NUM_LABELS
        ).to(self.device)
        self._model.eval()
        self._is_fine_tuned = True
        self._available = True

    def save_model(self, path: str) -> None:
        """Save current model and tokenizer to disk."""
        if not self._available:
            raise RuntimeError("No model loaded to save")

        out = Path(path)
        out.mkdir(parents=True, exist_ok=True)
        logger.info("Saving token classifier to %s", out)
        self._model.save_pretrained(out)
        self._tokenizer.save_pretrained(out)
