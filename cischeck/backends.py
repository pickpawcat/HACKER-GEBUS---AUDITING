"""Transports. WinRM for real targets; Mock for --demo (no network at all)."""
from __future__ import annotations

import json

from .collector import BackendError
from .demo_data import DEMO_SNAPSHOT


class WinRMBackend:
    """WinRM over NTLM. HTTP (5985) is message-encrypted by NTLM; --ssl adds TLS (5986)."""

    def __init__(self, host, username, password, port=5985, ssl=False, verify_cert=True, timeout=30):
        self.host, self.username, self._password = host, username, password
        self.port, self.ssl, self.verify_cert, self.timeout = port, ssl, verify_cert, timeout
        self._session = None

    def _connect(self):
        try:
            import winrm  # lazy: demo/dry-run/tests need no third-party packages
        except ImportError as exc:
            raise BackendError("pywinrm is not installed (pip install -r requirements.txt)") from exc
        scheme = "https" if self.ssl else "http"
        self._session = winrm.Session(
            f"{scheme}://{self.host}:{self.port}/wsman",
            auth=(self.username, self._password), transport="ntlm",
            server_cert_validation="validate" if self.verify_cert else "ignore",
            read_timeout_sec=self.timeout + 10, operation_timeout_sec=self.timeout,
        )

    def run(self, script: str) -> str:
        if self._session is None:
            self._connect()
        try:
            result = self._session.run_ps(script)
        except Exception as exc:  # pywinrm raises many transport-specific types
            raise BackendError(f"{type(exc).__name__}: {str(exc)[:200]}") from exc
        if result.status_code != 0:
            raise BackendError("remote PowerShell returned a non-zero exit code")
        return result.std_out.decode("utf-8", "replace")


class MockBackend:
    """Replays a canned snapshot so the whole pipeline can be demonstrated offline."""

    SECTION_ORDER = ["os", "registry", "netaccounts", "firewall", "guest", "defender", "services", "audit"]

    def __init__(self):
        self._calls = 0

    def run(self, script: str) -> str:
        section = self.SECTION_ORDER[self._calls]
        self._calls += 1
        data = DEMO_SNAPSHOT[section]
        if section == "netaccounts":
            data = {"text": data}
        return json.dumps(data)
