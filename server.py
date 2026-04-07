import os
from fastmcp import FastMCP
from mde import MdeClient

mcp = FastMCP("MDE MCP Server")

client = MdeClient(
    tenant_id=os.environ["TENANT_ID"],
    client_id=os.environ["CLIENT_ID"],
    client_secret=os.environ["CLIENT_SECRET"],
)


@mcp.tool()
def list_machines(limit: int = 50) -> list[dict]:
    """
    List Microsoft Defender for Endpoint machines (devices) visible.
    Use this first to discover machine IDs for other MDE tools.
    """
    return client.list_machines(limit=limit)


@mcp.tool()
def list_user_logon_machine(machine_id: str, limit: int = 50) -> list[dict]:
    """
    List users who logged on to a specific machine in Microsoft Defender for Endpoint.
    Requires a valid MDE machine_id (from list_machines).
    """
    return client.list_user_logon_machine(machine_id=machine_id, limit=limit)


@mcp.tool()
def get_machine_related_alerts(machine_id: str, limit: int = 50) -> list[dict]:
    """
    List alerts related to a specific machine in Microsoft Defender for Endpoint.
    Requires a valid MDE machine_id (from list_machines).
    """
    return client.get_machine_related_alerts(machine_id=machine_id, limit=limit)


@mcp.tool()
def list_alerts(limit: int = 50) -> list[dict]:
    """
    List Microsoft Defender for Endpoint alerts visible.
    """
    return client.list_alerts(limit=limit)


if __name__ == "__main__":
    mcp.run()