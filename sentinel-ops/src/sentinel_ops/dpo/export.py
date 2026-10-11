"""Export curated DPO trajectories into standard HuggingFace DPO trainer JSONL format."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger


def format_hf_dpo_record(entry: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Converts a logged DPOTrajectoryPair dict into HuggingFace {prompt, chosen, rejected} format."""
    prompt_raw = entry.get("prompt", "")
    target_service = entry.get("target_service", "checkout-service")
    chosen_traj = entry.get("chosen_trajectory") or []
    rejected_traj = entry.get("rejected_trajectory") or []

    if not prompt_raw or not chosen_traj or not rejected_traj or chosen_traj == rejected_traj:
        return None

    system_header = (
        f"You are Sentinel-Ops SRE Triage Agent analyzing target_service='{target_service}'. "
        "Cite only verified telemetry observations or abstain as INSUFFICIENT_EVIDENCE."
    )
    prompt = f"{system_header}\n\nAlert:\n{prompt_raw}"
    chosen = json.dumps(chosen_traj, ensure_ascii=False)
    rejected = json.dumps(rejected_traj, ensure_ascii=False)

    return {
        "prompt": prompt,
        "chosen": chosen,
        "rejected": rejected,
    }


def export_hf_dpo_dataset(
    input_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> int:
    """Reads recorded preference pairs and writes validated HuggingFace JSONL rows."""
    logger = DPOTrajectoryLogger(output_path=input_path)
    entries = logger.read_trajectories()

    base_dir = Path(__file__).resolve().parents[3]
    out_file = output_path or (base_dir / "data" / "dpo" / "hf_dpo_dataset.jsonl")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    seen_pairs: set[tuple[str, str, str]] = set()
    with open(out_file, "w", encoding="utf-8") as fp:
        for entry in entries:
            rec = format_hf_dpo_record(entry)
            if rec is None:
                continue
            dedup_key = (rec["prompt"], rec["chosen"], rec["rejected"])
            if dedup_key in seen_pairs:
                continue
            seen_pairs.add(dedup_key)
            fp.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Sentinel-Ops DPO trajectories to HuggingFace JSONL")
    parser.add_argument("--input", type=Path, default=None, help="Input trajectories.jsonl path")
    parser.add_argument("--output", type=Path, default=None, help="Output hf_dpo_dataset.jsonl path")
    args = parser.parse_args()

    count = export_hf_dpo_dataset(input_path=args.input, output_path=args.output)
    print(f"Exported {count} unique DPO training pairs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
