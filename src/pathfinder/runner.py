"""External tool runner with graceful degradation.

Every CLI wrapper resolves its binary first and reports MISSING_TOOL instead
of crashing, so a partial install still serves the tools it can.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    missing: str | None = None
    data: Any = None

    def as_error(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": "MISSING_TOOL" if self.missing else "ERROR",
            "error": self.missing or self.stderr.strip() or "unknown error",
        }
        if self.missing:
            payload["hint"] = (
                f"`{self.missing}` not found on PATH. See README for install instructions."
            )
        return payload


def resolve(name: str) -> str | None:
    """Absolute path to a CLI binary, or None if not installed."""
    return shutil.which(name)


def run(
    cmd: list[str],
    *,
    timeout: int = 300,
    stdin_data: str | None = None,
    binary: str | None = None,
) -> ToolResult:
    """Run an external command, returning a structured result."""
    if binary and not resolve(binary):
        return ToolResult(ok=False, missing=binary)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(ok=False, stderr=f"timeout after {timeout}s")
    except FileNotFoundError as exc:
        return ToolResult(ok=False, missing=str(exc.filename))

    return ToolResult(
        ok=proc.returncode == 0,
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
    )
