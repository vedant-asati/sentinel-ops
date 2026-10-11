"""Tests for HuggingFace DPO JSONL dataset export."""

import json
from pathlib import Path

from sentinel_ops.dpo.export import export_hf_dpo_dataset, format_hf_dpo_record
from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger


def test_format_hf_dpo_record_rejects_degenerate_pairs():
    assert format_hf_dpo_record({"prompt": "", "chosen_trajectory": [1], "rejected_trajectory": [2]}) is None
    assert format_hf_dpo_record({"prompt": "alert", "chosen_trajectory": [{"a": 1}], "rejected_trajectory": [{"a": 1}]}) is None


def test_export_hf_dpo_dataset_deduplicates_and_formats(tmp_path: Path):
    in_path = tmp_path / "trajectories.jsonl"
    out_path = tmp_path / "hf_dpo_dataset.jsonl"

    logger = DPOTrajectoryLogger(output_path=in_path)
    chosen = [{"role": "planner", "query": "payment_db_pool_acquire_timeouts_total"}]
    rejected = [{"role": "single_pass", "guess": "checkout-service"}]
    # Write identical pair twice + append a corrupted line
    logger.log_pair("inc_1", "Checkout latency 5s", "checkout-service", chosen, rejected)
    logger.log_pair("inc_2", "Checkout latency 5s", "checkout-service", chosen, rejected)
    with open(in_path, "a", encoding="utf-8") as fp:
        fp.write("CORRUPT_JSON_LINE\n")

    written = export_hf_dpo_dataset(input_path=in_path, output_path=out_path)
    assert written == 1
    lines = out_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert set(row.keys()) == {"prompt", "chosen", "rejected"}
    assert "Checkout latency 5s" in row["prompt"]
    assert "payment_db_pool_acquire_timeouts_total" in row["chosen"]
    assert "checkout-service" in row["rejected"]
