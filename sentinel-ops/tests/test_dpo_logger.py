from pathlib import Path
from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger


def test_dpo_trajectory_logger(tmp_path: Path):
    out_file = tmp_path / "test_trajectories.jsonl"
    logger = DPOTrajectoryLogger(output_path=out_file)

    chosen = [
        {"role": "supervisor", "action": "dispatched parallel metrics and trace specialists"},
        {"role": "evidence", "id": "EV-001", "finding": "payment db pool saturated at 2.0"},
        {"role": "claim", "statement": "payment-service is the root cause", "citations": ["EV-001"]},
        {"role": "adversarial", "verdict": "ACCEPTED"},
    ]
    rejected = [
        {"role": "single_pass", "action": "dumped raw telemetry to single prompt"},
        {"role": "claim", "statement": "checkout-service memory leak", "citations": []},
    ]

    logger.log_pair(
        incident_id="test_case_01",
        prompt="Alert: checkout latency 4.5s",
        target_service="checkout-service",
        chosen_steps=chosen,
        rejected_steps=rejected,
        metadata={"precision": 1.0},
    )

    records = logger.read_trajectories()
    assert len(records) == 1
    assert records[0]["incident_id"] == "test_case_01"
    assert len(records[0]["chosen_trajectory"]) == 4
    assert len(records[0]["rejected_trajectory"]) == 2
