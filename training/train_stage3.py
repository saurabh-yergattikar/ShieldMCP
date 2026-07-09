#!/usr/bin/env python3
"""Fine-tune DistilBERT for token-level instruction classification (Stage 3).

Trains a BIO tagger (O / B-INST / I-INST) on the JSONL data produced by
generate_stage3_data.py using the HuggingFace Trainer API.

Usage:
    python training/train_stage3.py \
        --train training/data/stage3_train.jsonl \
        --val   training/data/stage3_val.jsonl \
        --output models/stage3_token_classifier \
        --epochs 5 --batch-size 16 --lr 5e-5
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

LABEL_LIST = ["O", "B-INST", "I-INST"]
LABEL2ID = {l: i for i, l in enumerate(LABEL_LIST)}
ID2LABEL = {i: l for i, l in enumerate(LABEL_LIST)}
_IGNORE_INDEX = -100


def load_jsonl(path: Path) -> list[dict]:
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


class TokenClassificationDataset(Dataset):
    """Converts whitespace-tokenized BIO samples to subword-aligned examples."""

    def __init__(
        self,
        samples: list[dict],
        tokenizer: AutoTokenizer,
        max_length: int = 512,
    ) -> None:
        self.encodings: list[dict] = []

        for sample in samples:
            words = sample["tokens"]
            word_labels = [LABEL2ID.get(l, 0) for l in sample["labels"]]

            enc = tokenizer(
                words,
                is_split_into_words=True,
                truncation=True,
                max_length=max_length,
                padding=False,
            )

            word_ids = enc.word_ids()
            aligned_labels = []
            prev_word_id = None

            for wid in word_ids:
                if wid is None:
                    aligned_labels.append(_IGNORE_INDEX)
                elif wid != prev_word_id:
                    aligned_labels.append(word_labels[wid] if wid < len(word_labels) else 0)
                else:
                    label = word_labels[wid] if wid < len(word_labels) else 0
                    aligned_labels.append(
                        label if label == LABEL2ID["I-INST"] else
                        (LABEL2ID["I-INST"] if label == LABEL2ID["B-INST"] else label)
                    )
                prev_word_id = wid

            self.encodings.append({
                "input_ids": enc["input_ids"],
                "attention_mask": enc["attention_mask"],
                "labels": aligned_labels,
            })

    def __len__(self) -> int:
        return len(self.encodings)

    def __getitem__(self, idx: int) -> dict:
        return self.encodings[idx]


def compute_metrics(eval_pred: tuple) -> dict:
    """Per-label precision, recall, F1, and overall accuracy."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    mask = labels != _IGNORE_INDEX
    preds_flat = preds[mask]
    labels_flat = labels[mask]

    metrics: dict[str, float] = {}
    metrics["accuracy"] = (preds_flat == labels_flat).mean().item()

    for label_name, label_id in LABEL2ID.items():
        tp = ((preds_flat == label_id) & (labels_flat == label_id)).sum()
        fp = ((preds_flat == label_id) & (labels_flat != label_id)).sum()
        fn = ((preds_flat != label_id) & (labels_flat == label_id)).sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        tag = label_name.replace("-", "_").lower()
        metrics[f"precision_{tag}"] = float(precision)
        metrics[f"recall_{tag}"] = float(recall)
        metrics[f"f1_{tag}"] = float(f1)

    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Stage 3 token classifier")
    parser.add_argument("--train", type=str, default="training/data/stage3_train.jsonl")
    parser.add_argument("--val", type=str, default="training/data/stage3_val.jsonl")
    parser.add_argument("--output", type=str, default="models/stage3_token_classifier")
    parser.add_argument("--base-model", type=str, default="distilbert-base-uncased")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=5e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fp16", action="store_true", help="Use mixed precision (GPU only)")
    parser.add_argument("--logging-steps", type=int, default=50)
    parser.add_argument("--eval-strategy", type=str, default="epoch")
    parser.add_argument("--save-strategy", type=str, default="epoch")
    parser.add_argument("--load-best", action="store_true", default=True)
    args = parser.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Device: %s", device)

    logger.info("Loading tokenizer and model from %s", args.base_model)
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForTokenClassification.from_pretrained(
        args.base_model,
        num_labels=len(LABEL_LIST),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        ignore_mismatched_sizes=True,
    ).to(device)

    logger.info("Loading training data from %s", args.train)
    train_samples = load_jsonl(Path(args.train))
    logger.info("Loading validation data from %s", args.val)
    val_samples = load_jsonl(Path(args.val))

    logger.info("Tokenizing %d train / %d val samples", len(train_samples), len(val_samples))
    train_dataset = TokenClassificationDataset(train_samples, tokenizer, args.max_length)
    val_dataset = TokenClassificationDataset(val_samples, tokenizer, args.max_length)

    data_collator = DataCollatorForTokenClassification(tokenizer)

    output_dir = Path(args.output)
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        eval_strategy=args.eval_strategy,
        save_strategy=args.save_strategy,
        logging_steps=args.logging_steps,
        load_best_model_at_end=args.load_best,
        metric_for_best_model="f1_b_inst",
        greater_is_better=True,
        fp16=args.fp16 and device == "cuda",
        seed=args.seed,
        report_to="none",
        save_total_limit=2,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=data_collator,
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
    )

    logger.info("Starting training for %d epochs", args.epochs)
    trainer.train()

    logger.info("Saving best model to %s", output_dir)
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    logger.info("Running final evaluation")
    metrics = trainer.evaluate()
    for k, v in sorted(metrics.items()):
        logger.info("  %s: %.4f", k, v)

    metrics_path = output_dir / "eval_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info("Metrics saved to %s", metrics_path)


if __name__ == "__main__":
    main()
