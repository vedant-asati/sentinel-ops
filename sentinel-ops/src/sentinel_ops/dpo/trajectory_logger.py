import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DPOTrajectoryPair(BaseModel):
    """(Prompt, Chosen, Rejected) trajectory pair for DPO alignment fine-tuning."""
    incident_id: str
    prompt: str
    target_service: str
    chosen_trajectory: List[Dict[str, Any]] = Field(
        description="Grounded, evidence-backed steps verified by adversarial skeptic."
    )
    rejected_trajectory: List[Dict[str, Any]] = Field(
        description="Ungrounded, hallucinated, or unverified steps from baseline/unsupported runs."
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DPOTrajectoryLogger:
    """Appends pairwise preference trajectories to data/dpo/trajectories.jsonl."""

    def __init__(self, output_path: Optional[Path] = None):
        if output_path:
            self.output_path = output_path
        else:
            # Default to repo root / data / dpo / trajectories.jsonl
            base_dir = Path(__file__).resolve().parents[3]
            self.output_path = base_dir / "data" / "dpo" / "trajectories.jsonl"
        
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def log_pair(
        self,
        incident_id: str,
        prompt: str,
        target_service: str,
        chosen_steps: List[Dict[str, Any]],
        rejected_steps: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Appends a new pairwise trajectory to the JSONL dataset."""
        record = DPOTrajectoryPair(
            incident_id=incident_id,
            prompt=prompt,
            target_service=target_service,
            chosen_trajectory=chosen_steps,
            rejected_trajectory=rejected_steps,
            metadata=metadata or {},
        )

        with open(self.output_path, "a", encoding="utf-8") as fp:
            fp.write(record.model_dump_json() + "\n")

        return self.output_path

    def read_trajectories(self) -> List[Dict[str, Any]]:
        """Reads all logged trajectory pairs."""
        if not self.output_path.exists():
            return []
        entries = []
        with open(self.output_path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries
