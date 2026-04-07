import requests
from dataclasses import dataclass
from typing import Any


@dataclass
class MdeClient:
    tenant_id: str
    client_id: str
    client_secret: str
    _token: str | None = None

    def _get_token(self, resource: str = "https://api.securitycenter.microsoft.com/") -> str:
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"
        resp = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "resource": resource,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def list_machines(self, limit: int = 50) -> list[dict[str, Any]]:
        """List Microsoft Defender for Endpoint machines.
        Args:
            limit: Max number of returned items.
        Returns:
            List of machine objects as dicts.
        """
        token = self._get_token()
        url = "https://api.security.microsoft.com/api/machines"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        return resp.json().get("value", [])[:limit]

    def list_user_logon_machine(self, machine_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """List users who logged on to a specific machine.
        Args:
            machine_id: MDE machine id.
            limit: Max number of returned items.
        Returns:
            List of logon user records as dicts.
        """
        token = self._get_token()
        url = f"https://api.security.microsoft.com/api/machines/{machine_id}/logonusers"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        return resp.json().get("value", [])[:limit]

    def get_machine_related_alerts(self, machine_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """List alerts related to a specific machine.
        Args:
            machine_id: MDE machine id.
            limit: Max number of returned items.
        Returns:
            List of alerts as dicts.
        """
        token = self._get_token()
        # Some tenants support this endpoint directly; if yours doesn't, use list_alerts() + filter.
        url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/alerts"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 404:
            # Fallback: pull alerts and filter client-side (less efficient).
            return [a for a in self.list_alerts(limit=1000) if a.get("machineId") == machine_id][:limit]
        resp.raise_for_status()
        return resp.json().get("value", [])[:limit]

    def list_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """List Microsoft Defender for Endpoint alerts.
        Args:
            limit: Max number of returned items.
        Returns:
            List of alert objects as dicts.
        """
        token = self._get_token()
        url = "https://api.securitycenter.microsoft.com/api/alerts"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        return resp.json().get("value", [])[:limit]