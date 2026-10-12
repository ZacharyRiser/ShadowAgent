"""Run the full backend suite and report exact counts.

pytest's own summary line is lost when stdout is redirected, so counts are
derived from the progress characters with a strict regex: a loose one picks up
dots/s/E inside absolute Windows paths such as `..\\..\\Environments`.
"""
import re
import subprocess
import sys

proc = subprocess.run(
    [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:warnings"],
    capture_output=True,
    text=True,
)
out = proc.stdout + proc.stderr
counts = {"passed": 0, "skipped": 0, "failed": 0, "errors": 0}
for line in out.splitlines():
    match = re.match(r"^([.sFE]+)\s+\[\s*\d+%\]$", line.strip())
    if match:
        seq = match.group(1)
        counts["passed"] += seq.count(".")
        counts["skipped"] += seq.count("s")
        counts["failed"] += seq.count("F")
        counts["errors"] += seq.count("E")

print("exit code :", proc.returncode)
print("counts    :", counts)
print("collected :", sum(counts.values()))
if proc.returncode != 0:
    print("--- failures ---")
    print("\n".join(line for line in out.splitlines() if "FAILED" in line or "ERROR" in line))
