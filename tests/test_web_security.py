"""Offline tests for web authentication and browser/deployment hardening."""

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from obscuralens.web import create_app  # noqa: E402
from obscuralens.web.app import (  # noqa: E402
    LOOPBACK_HOSTS,
    WEB_TOKEN_ENV,
    _ensure_secure_bind,
    _is_loopback_host,
    _StreamTicketStore,
)

TEST_TOKEN = "unit-test-only_7f3ab60a9c744d48a11b0c2ed98f7251"
AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture()
def secure_client():
    with TestClient(create_app(api_token=TEST_TOKEN)) as client:
        yield client


class TestBearerAuthentication:
    def test_health_is_public_and_reports_auth_without_secret(self, secure_client):
        response = secure_client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["authentication_required"] is True
        assert TEST_TOKEN not in response.text

    def test_api_rejects_missing_wrong_and_query_credentials(self, secure_client):
        for headers in ({}, {"Authorization": "Bearer wrong"},
                        {"Authorization": TEST_TOKEN},
                        {"X-API-Key": "wrong"}):
            response = secure_client.get("/api/kinds", headers=headers)
            assert response.status_code == 401
            assert response.json() == {"detail": "authentication required"}
            assert response.headers["WWW-Authenticate"] == "Bearer"
        assert secure_client.get(
            "/api/kinds", params={"access_token": TEST_TOKEN}).status_code == 401

    def test_valid_credentials_unlock_api_and_static_shell_stays_loadable(
            self, secure_client):
        assert secure_client.get("/api/kinds", headers=AUTH).status_code == 200
        # Both shipped SDKs already send X-API-Key; native auth must not break
        # their existing transport contract.
        assert secure_client.get(
            "/api/kinds", headers={"X-API-Key": TEST_TOKEN}).status_code == 200
        assert secure_client.get("/").status_code == 200

    def test_python_sdk_api_key_works_end_to_end(self, secure_client):
        from obscuralens.sdk.client import ObscuraLensClient
        from obscuralens.sdk.transport import Response

        class TestClientTransport:
            def request(self, method, url, headers=None, params=None,
                        json_body=None, body=None, timeout=None):
                from urllib.parse import urlsplit
                target = urlsplit(url)
                path = target.path + (f"?{target.query}" if target.query else "")
                response = secure_client.request(
                    method, path, headers=headers, json=json_body,
                    content=body)
                return Response(response.status_code,
                                dict(response.headers), response.content)

            def close(self):
                return None

        sdk = ObscuraLensClient(
            base_url="http://testserver", api_key=TEST_TOKEN,
            transport=TestClientTransport())
        assert len(sdk.kinds()) == 20
        sdk.close()

    def test_unconfigured_server_keeps_backward_compatible_local_api(self):
        client = TestClient(create_app(api_token=""))
        assert client.get("/api/health").json()[
            "authentication_required"] is False
        assert client.get("/api/kinds").status_code == 200

    def test_openapi_advertises_bearer_on_sensitive_operations(self, secure_client):
        schema = secure_client.get("/openapi.json").json()
        assert schema["components"]["securitySchemes"]["bearerAuth"] == {
            "type": "http", "scheme": "bearer", "bearerFormat": WEB_TOKEN_ENV,
        }
        assert "security" not in schema["paths"]["/api/health"]["get"]
        assert schema["components"]["securitySchemes"]["apiKeyAuth"] == {
            "type": "apiKey", "in": "header", "name": "X-API-Key",
        }
        assert schema["paths"]["/api/kinds"]["get"]["security"] == [
            {"bearerAuth": []}, {"apiKeyAuth": []}]


class TestStreamTickets:
    def test_ticket_endpoint_requires_bearer(self, secure_client):
        assert secure_client.post("/api/stream/ticket").status_code == 401

    def test_ticket_is_single_use_and_scoped_to_stream(self, secure_client):
        issued = secure_client.post("/api/stream/ticket", headers=AUTH)
        assert issued.status_code == 200
        ticket = issued.json()["ticket"]
        assert issued.json()["expires_in"] == 30

        # A ticket cannot unlock an ordinary endpoint and is not consumed there.
        assert secure_client.get(
            "/api/kinds", params={"ticket": ticket}).status_code == 401
        first = secure_client.get(
            "/api/stream", params={"ticket": ticket, "max_events": 1},
            timeout=10)
        assert first.status_code == 200
        assert first.text.startswith("event: connected")
        replay = secure_client.get(
            "/api/stream", params={"ticket": ticket, "max_events": 1})
        assert replay.status_code == 401

    def test_stream_still_accepts_normal_bearer_for_non_browser_clients(
            self, secure_client):
        response = secure_client.get(
            "/api/stream?max_events=1", headers=AUTH, timeout=10)
        assert response.status_code == 200

    def test_store_expires_and_bounds_tickets(self):
        now = [100.0]
        store = _StreamTicketStore(ttl=5, capacity=2, clock=lambda: now[0])
        first = store.issue()
        second = store.issue()
        third = store.issue()  # bounded capacity evicts the oldest
        assert not store.consume(first)
        now[0] = 106.0
        assert not store.consume(second)
        assert not store.consume(second)  # expired tickets are also single-use
        assert not store.consume(third)
        fresh = store.issue()
        assert store.consume(fresh)
        assert not store.consume(fresh)


class TestResponseAndHostHardening:
    def test_security_headers_on_api_and_spa(self, secure_client):
        api = secure_client.get("/api/health")
        assert api.headers["Cache-Control"] == "no-store"
        assert api.headers["X-Content-Type-Options"] == "nosniff"
        assert api.headers["X-Frame-Options"] == "DENY"
        assert api.headers["Referrer-Policy"] == "no-referrer"
        assert api.headers["Cross-Origin-Resource-Policy"] == "same-origin"
        page = secure_client.get("/")
        csp = page.headers["Content-Security-Policy"]
        assert "script-src 'self';" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_loopback_host_allowlist_rejects_dns_rebinding(self):
        client = TestClient(create_app(allowed_hosts=list(LOOPBACK_HOSTS)))
        assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400
        assert client.get("/", headers={"Host": "127.0.0.1:8000"}).status_code == 200


class TestBindSafety:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]"])
    def test_loopback_hosts_are_detected(self, host):
        assert _is_loopback_host(host)

    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "example.com", ""])
    def test_public_or_ambiguous_hosts_are_not_loopback(self, host):
        assert not _is_loopback_host(host)

    def test_non_loopback_requires_token_or_explicit_override(self):
        with pytest.raises(ValueError, match="refusing to expose"):
            _ensure_secure_bind("0.0.0.0")
        _ensure_secure_bind("0.0.0.0", TEST_TOKEN)
        _ensure_secure_bind("0.0.0.0", allow_unauthenticated=True)
        _ensure_secure_bind("127.0.0.1")

    def test_serve_fails_before_opening_a_public_unauthenticated_socket(
            self, monkeypatch):
        from obscuralens.web import serve
        monkeypatch.delenv(WEB_TOKEN_ENV, raising=False)
        with pytest.raises(ValueError, match=WEB_TOKEN_ENV):
            serve(host="0.0.0.0", api_token="", open_browser=False)

    def test_cli_exposes_explicit_override(self):
        from obscuralens.commands import build_parser
        args = build_parser().parse_args(["serve", "--allow-unauthenticated"])
        assert args.allow_unauthenticated is True
        assert build_parser().parse_args(["serve"]).allow_unauthenticated is False
