#!/usr/bin/env python3
"""Fine-tune DistilBERT for Stage 1 semantic intent classification.

Trains a binary classifier to detect adversarial tool descriptions
(label 1) vs benign descriptions (label 0).

Usage:
    python training/train_stage1.py \
        --train-file training/data/stage1_train.jsonl \
        --val-file training/data/stage1_val.jsonl \
        --output-dir models/stage1_classifier \
        --epochs 4 \
        --batch-size 16 \
        --learning-rate 2e-5
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import torch
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from torch.utils.data import Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "distilbert-base-uncased"
_MAX_LENGTH = 512


class DescriptionDataset(Dataset):
    """JSONL-backed dataset for tool descriptions."""

    def __init__(self, path: str | Path, tokenizer: AutoTokenizer, max_length: int = _MAX_LENGTH):
        self.samples: list[dict] = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    self.samples.append(json.loads(line))

        self.encodings = tokenizer(
            [s["text"] for s in self.samples],
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        self.labels = torch.tensor([s["label"] for s in self.samples], dtype=torch.long)

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        item = {k: v[idx] for k, v in self.encodings.items()}
        item["labels"] = self.labels[idx]
        return item


def compute_metrics(eval_pred) -> dict[str, float]:  # type: ignore[no-untyped-def]
    logits, labels = eval_pred
    preds = logits.argmax(axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, zero_division=0),
        "precision": precision_score(labels, preds, zero_division=0),
        "recall": recall_score(labels, preds, zero_division=0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Stage 1 classifier")
    parser.add_argument("--train-file", type=str, default="training/data/stage1_train.jsonl")
    parser.add_argument("--val-file", type=str, default="training/data/stage1_val.jsonl")
    parser.add_argument("--base-model", type=str, default=_DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=str, default="models/stage1_classifier")
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--eval-steps", type=int, default=100)
    parser.add_argument("--save-steps", type=int, default=200)
    parser.add_argument("--fp16", action="store_true", help="Use mixed precision (GPU only)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--early-stopping-patience", type=int, default=3,
        help="Stop if val loss doesn't improve for N evaluations",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for path in [args.train_file, args.val_file]:
        if not Path(path).exists():
            logger.error("Data file not found: %s — run generate_stage1_data.py first", path)
            sys.exit(1)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Using device: %s", device)
    if args.fp16 and device == "cpu":
        logger.warning("--fp16 ignored on CPU")
        args.fp16 = False

    logger.info("Loading tokenizer and model: %s", args.base_model)
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=2,
        id2label={0: "benign", 1: "malicious"},
        label2id={"benign": 0, "malicious": 1},
    )

    logger.info("Loading training data from %s", args.train_file)
    train_dataset = DescriptionDataset(args.train_file, tokenizer)
    logger.info("Training samples: %d", len(train_dataset))

    logger.info("Loading validation data from %s", args.val_file)
    val_dataset = DescriptionDataset(args.val_file, tokenizer)
    logger.info("Validation samples: %d", len(val_dataset))

    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        eval_strategy="steps",
        eval_steps=args.eval_steps,
        save_strategy="steps",
        save_steps=args.save_steps,
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        fp16=args.fp16,
        logging_steps=50,
        logging_first_step=True,
        report_to="none",
        seed=args.seed,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=args.early_stopping_patience)],
    )

    logger.info("Starting training...")
    train_result = trainer.train()
    logger.info("Training complete. Metrics: %s", train_result.metrics)

    logger.info("Running final evaluation...")
    eval_metrics = trainer.evaluate()
    logger.info("Eval metrics: %s", eval_metrics)

    logger.info("Saving model to %s", output_dir)
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    metrics_path = output_dir / "training_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(
            {"train": train_result.metrics, "eval": eval_metrics, "args": vars(args)},
            f,
            indent=2,
        )
    logger.info("Metrics saved to %s", metrics_path)


if __name__ == "__main__":
    main()
