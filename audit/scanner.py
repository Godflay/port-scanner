from __future__ import annotations

import subprocess
from typing import List, Optional
from dataclasses import dataclass


class ScannerError(RuntimeError):
    """Raised when we fail to run 'ss' command or unnusual output is detected"""


@dataclass(slots=True)
class ScanResult:
    command: List[str]
    stdout: str
    stderr: str
    returncode: int

def scan_listening_ports() -> ScanResult:
    """
    scan listening ports using 'ss -ltnup' command
    """
    cmd = ["ss", "-ltnup"]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
    except FileNotFoundError as e:
        raise ScannerError("'ss' not found install package 'iproute2'") from e
    
    except Exception as e:
        raise ScannerError("Failed to run 'ss' command: {e}") from e
    
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    #if ss return nonthing, it can mean no port or perms issues
    #we accept empty stdout as valid but still return metadata

    return ScanResult(
        command=cmd,
        stdout=stdout,
        stderr=stderr,
        returncode=completed.returncode
    )

def scan_text_or_raise(result: ScanResult) -> str:
    """
    little helper, returns stdout if scan looks sane, raise ScannerError otherwise
    """
    if result.returncode != 0:
        msg = result.stderr.strip() or "Unknown error"
        raise ScannerError(
            f"'ss' command failed with return code {result.returncode}: {msg}"
        )
    
    return result.stdout