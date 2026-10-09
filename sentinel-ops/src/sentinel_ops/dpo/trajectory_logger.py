import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)


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

    @model_validator(mode="after")
    def validate_trajectories(self) -> "DPOTrajectoryPair":
        if not self.chosen_trajectory:
            raise ValueError("chosen_trajectory cannot be empty")
        if not self.rejected_trajectory:
            raise ValueError("rejected_trajectory cannot be empty")
        if self.chosen_trajectory == self.rejected_trajectory:
            raise ValueError("chosen_trajectory and rejected_trajectory cannot be identical")
        return self


class DPOTrajectoryLogger:
    """Appends pairwise preference trajectories to data/dpo/trajectories.jsonl."""

    def __init__(self, output_path: Optional[Path] = None):
        if output_path:
            self.output_path = output_path
        else:
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
        """Appends a new pairwise trajectory to the JSONL dataset with file locking."""
        record = DPOTrajectoryPair(
            incident_id=incident_id,
            prompt=prompt,
            target_service=target_service,
            chosen_trajectory=chosen_steps,
            rejected_trajectory=rejected_steps,
            metadata=metadata or {},
        )

        with open(self.output_path, "a", encoding="utf-8") as fp:
            try:
                import fcntl
                fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            except (ImportError, OSError):
                pass
            try:
                fp.write(record.model_dump_json() + "\n")
                fp.flush()
            finally:
                try:
                    import fcntl
                    fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass

        return self.output_path

    def read_trajectories(self) -> List[Dict[str, Any]]:
        """Reads all logged trajectory pairs, gracefully skipping corrupted lines."""
        if not self.output_path.exists():
            return []
        entries = []
        with open(self.output_path, "r", encoding="utf-8") as fp:
            for line_no, line in enumerate(fp, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except (json.JSONDecodeError, ValueError) as err:
                    logger.warning("Skipping corrupted line %d in %s: %s", line_no, self.output_path, err)
                    continue
        return entries
