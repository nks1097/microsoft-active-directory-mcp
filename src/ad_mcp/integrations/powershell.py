"""
PowerShell integration layer for Active Directory MCP Server.
Executes parameterized PowerShell scripts securely with JSON serialization,
timeout controls, and fallback to .NET ADSI when RSAT is unavailable.
"""

import base64
import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Optional, Tuple

from ad_mcp.config import settings

logger = logging.getLogger("ad_mcp.powershell")


class PowerShellClient:
    """Manages secure execution of PowerShell commands and scripts."""

    def __init__(self, executable_path: Optional[str] = None):
        self.executable = executable_path or self._find_powershell()
        self._rsat_available: Optional[bool] = None

    def _find_powershell(self) -> str:
        """Find pwsh (PowerShell 7+) or fallback to powershell.exe."""
        if settings.powershell_path and os.path.exists(settings.powershell_path):
            return settings.powershell_path
        pwsh = shutil.which("pwsh")
        if pwsh:
            return pwsh
        ps = shutil.which("powershell.exe") or shutil.which("powershell")
        if ps:
            return ps
        # Default Windows path fallback
        default_win_ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        if os.path.exists(default_win_ps):
            return default_win_ps
        return "powershell"

    def is_available(self) -> bool:
        """Check if PowerShell executable exists and responds."""
        try:
            res = subprocess.run(
                [self.executable, "-NoProfile", "-NonInteractive", "-Command", "Write-Output 'OK'"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0 and "OK" in res.stdout
        except Exception:
            return False

    def check_rsat(self) -> bool:
        """Check if ActiveDirectory module is installed."""
        if self._rsat_available is not None:
            return self._rsat_available
        script = "if (Get-Module -ListAvailable ActiveDirectory) { Write-Output 'RSAT_PRESENT' } else { Write-Output 'RSAT_ABSENT' }"
        success, out, _ = self.execute_script(script)
        self._rsat_available = success and isinstance(out, str) and "RSAT_PRESENT" in out
        return self._rsat_available

    def execute_script(
        self,
        script: str,
        timeout: Optional[int] = None,
        as_json: bool = False,
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Execute a PowerShell script using UTF-16LE Base64 -EncodedCommand.
        Returns:
            (success, data_or_stdout, error_message)
        """
        timeout_seconds = timeout or settings.timeout_seconds

        # Wrap in JSON conversion if requested
        if as_json:
            full_script = f"""
            $ErrorActionPreference = 'Stop'
            try {{
                $result = & {{
                    {script}
                }}
                if ($null -ne $result) {{
                    $json = $result | ConvertTo-Json -Compress -Depth 10
                    Write-Output "__JSON_START__"
                    Write-Output $json
                    Write-Output "__JSON_END__"
                }}
            }} catch {{
                Write-Error $_.Exception.Message
                exit 1
            }}
            """
        else:
            full_script = script

        # Encode command in UTF-16LE for PowerShell -EncodedCommand
        encoded = base64.b64encode(full_script.encode("utf-16le")).decode("utf-8")

        cmd = [
            self.executable,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ]

        try:
            start_time = time.time()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            time.time() - start_time

            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()

            if proc.returncode != 0:
                err_msg = stderr or stdout or f"Process exited with code {proc.returncode}"
                return False, None, err_msg

            if as_json and "__JSON_START__" in stdout:
                try:
                    start_marker = "__JSON_START__"
                    end_marker = "__JSON_END__"
                    start_idx = stdout.find(start_marker) + len(start_marker)
                    end_idx = stdout.find(end_marker)
                    json_str = stdout[start_idx:end_idx].strip()
                    parsed = json.loads(json_str)
                    return True, parsed, None
                except Exception as je:
                    logger.warning(f"Failed to parse JSON output: {je}. Raw output: {stdout}")
                    return True, stdout, None

            return True, stdout, None

        except subprocess.TimeoutExpired:
            return False, None, f"Execution timed out after {timeout_seconds} seconds"
        except Exception as e:
            return False, None, str(e)


powershell_client = PowerShellClient()
