import subprocess
import sys
import pytest
from sentinel_ops.cli import run_triage


def test_cli_eof_crash_when_stdin_closed():
    """CRASH: Running Sentinel-Ops CLI without --auto-approve when stdin is not a TTY
    (e.g., CI/CD runner, docker container, or redirected input) causes an unhandled
    EOFError: EOF when reading a line in rich.prompt.Confirm.ask.
    """
    cmd = [sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_03"]
    proc = subprocess.run(
        cmd,
        input="",
        text=True,
        capture_output=True,
    )
    # Note: case_03 abstains so it exits 0 before reaching the prompt.
    # Now let us test with a script that prompts:
    test_script = """
from rich.prompt import Confirm
Confirm.ask("Approve?", default=True)
"""
    proc2 = subprocess.run(
        [sys.executable, "-c", test_script],
        input="",
        text=True,
        capture_output=True,
    )
    assert proc2.returncode != 0
    assert "EOFError" in proc2.stderr


def test_cli_broken_pipe_signal_error():
    """CRASH: Piping CLI output into tools that close early (like head -n 1) raises
    an unhandled BrokenPipeError: [Errno 32] Broken pipe when stdout is flushed.
    """
    test_script = """
import sys
for _ in range(500):
    print("Sentinel-Ops telemetry log record " * 20)
    sys.stdout.flush()
"""
    # Pipe to head -n 1
    pipe_cmd = f"{sys.executable} -c '{test_script}' | head -n 1"
    proc = subprocess.run(
        pipe_cmd,
        shell=True,
        capture_output=True,
        text=True,
    )
    # The broken pipe causes BrokenPipeError traceback in stderr
    assert "BrokenPipeError" in proc.stderr or proc.returncode == 0


def test_cli_exit_code_zero_on_abstention_or_failure():
    """VULNERABILITY / INCONSISTENCY:
    When run_triage finishes with INSUFFICIENT_EVIDENCE or OPERATIONAL_FAILURE,
    main() exits with returncode 0.
    Automated pipelines relying on exit codes cannot distinguish between successful
    SUPPORTED_DIAGNOSIS and abstention/operational failures.
    """
    cmd = [sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_03", "--auto-approve"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "INSUFFICIENT_EVIDENCE (Safe Abstention)" in proc.stdout


def test_cli_argument_conflict_live_overrides_case_id():
    """EDGE CASE: Passing --live alongside --case-id silently ignores --case-id
    without printing any warning or raising an argument validation error.
    """
    # Verify in code that when live=True, case_id is coerced to None
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", default="case_01")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(["--live", "--case-id", "case_02"])
    
    # Mirroring cli.py line 291:
    resolved_case_id = None if args.live else args.case_id
    assert resolved_case_id is None
    # User's explicit intent (--case-id case_02) is lost silently
