import subprocess
import sys


def test_cli_eof_crash_when_stdin_closed():
    """INVARIANT: Running Sentinel-Ops CLI without --auto-approve on a closed stdin safely defers instead of crashing with EOFError."""
    cmd = [sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_01", "--no-dpo"]
    proc = subprocess.run(cmd, input="", text=True, capture_output=True)
    assert proc.returncode == 0
    assert "EOFError" not in proc.stderr


def test_cli_broken_pipe_signal_error():
    """INVARIANT: Piping CLI output to head -n 1 exits cleanly without BrokenPipeError tracebacks."""
    pipe_cmd = f"{sys.executable} -m sentinel_ops.cli --case-id case_01 --auto-approve --no-dpo | head -n 1"
    proc = subprocess.run(pipe_cmd, shell=True, capture_output=True, text=True)
    assert "BrokenPipeError" not in proc.stderr


def test_cli_exit_code_zero_on_abstention_or_failure():
    """INVARIANT: CLI exposes distinct semantic exit codes: 0 for diagnosis, 2 for safe abstention."""
    cmd_diag = [sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_01", "--auto-approve", "--no-dpo"]
    proc_diag = subprocess.run(cmd_diag, capture_output=True, text=True)
    assert proc_diag.returncode == 0

    cmd_abstain = [sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_03", "--auto-approve", "--no-dpo"]
    proc_abstain = subprocess.run(cmd_abstain, capture_output=True, text=True)
    assert proc_abstain.returncode == 2
    assert "INSUFFICIENT_EVIDENCE (Safe Abstention)" in proc_abstain.stdout


def test_cli_argument_conflict_live_overrides_case_id():
    """INVARIANT: Passing --live together with --case-id rejects ambiguous intent with explicit error."""
    cmd = [sys.executable, "-m", "sentinel_ops.cli", "--live", "--case-id", "case_02", "--no-dpo"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode != 0
    assert "Cannot combine --live with --case-id" in proc.stderr
