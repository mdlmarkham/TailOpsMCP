import pytest

from src import mcp_server


@pytest.mark.asyncio
async def test_file_operations_respects_allowlist(monkeypatch):
    """file_operations should deny access when filesec rejects a path."""

    def fake_is_path_allowed(path):
        return False, "path blocked"

    monkeypatch.setattr("utils.filesec.is_path_allowed", fake_is_path_allowed)

    result = await mcp_server.file_operations.fn.__wrapped__(
        action="list",
        path="/tmp",
        lines=10,
        offset=0,
        pattern="*",
    )

    assert result["success"] is False
    assert "path blocked" in result["error"]


@pytest.mark.asyncio
async def test_ping_host_rejects_blocked_host(monkeypatch):
    """ping_host must refuse disallowed hosts before spawning ping."""

    def fake_is_host_allowed(host):
        return False, "host blocked"

    def fail_run(*args, **kwargs):  # pragma: no cover - should not run
        raise AssertionError("ping should not execute for blocked hosts")

    monkeypatch.setattr("utils.netsec.is_host_allowed", fake_is_host_allowed)
    monkeypatch.setattr("subprocess.run", fail_run)

    result = await mcp_server.ping_host.fn.__wrapped__(
        host="10.0.0.1",
        count=1,
        format="json",
    )

    assert result["success"] is False
    assert "host blocked" in result["error"]


@pytest.mark.asyncio
async def test_test_port_connectivity_rejects_blocked_port(monkeypatch):
    """test_port_connectivity should stop when a port is not allowlisted."""

    def fake_is_host_allowed(host):
        return True, "host ok"

    def fake_is_port_allowed(port):
        return False, "port blocked"

    class FailSocket:
        def __init__(self, *args, **kwargs):  # pragma: no cover - should not run
            raise AssertionError("socket should not be created for blocked ports")

    monkeypatch.setattr("utils.netsec.is_host_allowed", fake_is_host_allowed)
    monkeypatch.setattr("utils.netsec.is_port_allowed", fake_is_port_allowed)
    monkeypatch.setattr("socket.socket", FailSocket)

    result = await mcp_server.test_port_connectivity.fn.__wrapped__(
        host="example.com",
        port=1234,
        ports=None,
        timeout=1,
    )

    assert result["success"] is False
    assert "port blocked" in result["error"].lower()


@pytest.mark.asyncio
async def test_http_request_test_rejects_blocked_url(monkeypatch):
    """http_request_test must deny blocked URLs before issuing requests."""

    def fake_is_url_allowed(url):
        return False, "url blocked"

    def fail_request(*args, **kwargs):  # pragma: no cover - should not run
        raise AssertionError("HTTP request should not run for blocked URLs")

    monkeypatch.setattr("utils.netsec.is_url_allowed", fake_is_url_allowed)
    monkeypatch.setattr("requests.request", fail_request)

    result = await mcp_server.http_request_test.fn.__wrapped__(
        url="http://169.254.169.254/latest/meta-data/",
        method="GET",
        timeout=5,
    )

    assert result["success"] is False
    assert "url blocked" in result["error"]
