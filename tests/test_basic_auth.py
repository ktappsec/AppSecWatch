"""HTTP Basic front door (`auth.BasicAuthMiddleware`).

The point of this layer is reach: `require_api_key` is a per-route dependency and
the built UI is mounted as plain static files with none, so before this the SPA
shell was served anonymously. These tests pin BOTH halves — that Basic covers the
static mount, and that it interoperates with the existing API key rather than
replacing it.
"""
from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from appsecwatch.api.config import ServerConfig, parse_basic_auth
from appsecwatch.api.server import create_app, create_combined_app

API_KEY = "secret-key-1"
USER, PASSWORD = "opsuser", "s3cr3t:with:colons"


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _config(tmp_path, *, api_keys=(API_KEY,), basic=(USER, PASSWORD)) -> ServerConfig:
    return ServerConfig(
        output_root=str(tmp_path / "runs"),
        base_config_raw={
            "mmdb_path": "/dev/null",
            "llm": {"base_url": "http://llm.local", "model": "test-model"},
        },
        api_keys=list(api_keys),
        basic_auth_user=basic[0] if basic else None,
        basic_auth_password=basic[1] if basic else None,
    )


def _ui_dir(tmp_path):
    """A minimal built-UI directory, so the static mount has something to serve."""
    d = tmp_path / "ui"
    d.mkdir(parents=True, exist_ok=True)
    (d / "index.html").write_text("<html><body>APPSECWATCH UI</body></html>")
    (d / "app.js").write_text("console.log('ui')")
    return d


# --------------------------------------------------------------------------- #
# parse_basic_auth
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("user:pass", ("user", "pass")),
    # RFC 7617 allows ':' in the password — split on the FIRST one only.
    ("user:pa:ss:word", ("user", "pa:ss:word")),
    ("  user  :pass", ("user", "pass")),         # username trimmed
    ("user: pass ", ("user", " pass ")),         # password NOT trimmed
    (None, (None, None)),
    ("", (None, None)),
    ("nocolon", (None, None)),
    (":onlypass", (None, None)),                 # empty user
    ("onlyuser:", (None, None)),                 # empty password
])
def test_parse_basic_auth(raw, expected):
    assert parse_basic_auth(raw) == expected


def test_half_configured_pair_disables_rather_than_locks_out(tmp_path):
    """A malformed value must not produce a gate nobody can pass."""
    cfg = _config(tmp_path, basic=None)
    assert cfg.basic_auth_enabled is False


# --------------------------------------------------------------------------- #
# Standalone app
# --------------------------------------------------------------------------- #

def test_challenges_unauthenticated_request(tmp_path):
    with TestClient(create_app(_config(tmp_path))) as c:
        r = c.get("/capabilities")
    assert r.status_code == 401
    # The realm is what the browser prompts on and caches against.
    assert 'Basic realm="AppSecWatch"' in r.headers["WWW-Authenticate"]
    assert r.json()["error"]["code"] == "unauthorized"


def test_basic_credentials_accepted(tmp_path):
    with TestClient(create_app(_config(tmp_path))) as c:
        r = c.get("/capabilities", headers=_basic(USER, PASSWORD))
    assert r.status_code == 200


def test_basic_alone_satisfies_require_api_key(tmp_path):
    """A human who cleared the front door must not ALSO need the 64-char key."""
    with TestClient(create_app(_config(tmp_path))) as c:
        r = c.get("/assets", headers=_basic(USER, PASSWORD))
    assert r.status_code == 200


def test_api_key_alone_still_works(tmp_path):
    """Scripts and `?api_key=` links must keep working un-prompted."""
    with TestClient(create_app(_config(tmp_path))) as c:
        assert c.get("/assets", headers={"Authorization": f"Bearer {API_KEY}"}).status_code == 200
        assert c.get("/assets", headers={"X-API-Key": API_KEY}).status_code == 200
        assert c.get(f"/assets?api_key={API_KEY}").status_code == 200


@pytest.mark.parametrize("user,password", [
    (USER, "wrong"),
    ("wrong", PASSWORD),
    ("wrong", "wrong"),
])
def test_wrong_credentials_rejected(tmp_path, user, password):
    with TestClient(create_app(_config(tmp_path))) as c:
        r = c.get("/capabilities", headers=_basic(user, password))
    assert r.status_code == 401


@pytest.mark.parametrize("header", [
    "Basic !!!not-base64!!!",
    "Basic " + base64.b64encode(b"no-colon-here").decode(),
    "Basic ",
    "Bogus abc",
])
def test_malformed_authorization_rejected(tmp_path, header):
    with TestClient(create_app(_config(tmp_path))) as c:
        r = c.get("/capabilities", headers={"Authorization": header})
    assert r.status_code == 401


def test_healthz_never_challenged(tmp_path):
    """deploy.sh polls this; a health check gated on credentials reports the
    wrong thing precisely when credentials are what broke."""
    with TestClient(create_app(_config(tmp_path))) as c:
        r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_disabled_when_unconfigured(tmp_path):
    """With no Basic pair the middleware is a pass-through — the API key alone
    governs, exactly as before this feature."""
    cfg = _config(tmp_path, basic=None)
    with TestClient(create_app(cfg)) as c:
        assert c.get("/capabilities").status_code == 401          # key still required
        assert c.get("/capabilities",
                     headers={"Authorization": f"Bearer {API_KEY}"}).status_code == 200


def test_basic_only_deployment_has_no_open_api(tmp_path):
    """Basic configured but NO api_keys: `auth_enabled` is False, so
    `require_api_key` would return early — the middleware must still gate."""
    cfg = _config(tmp_path, api_keys=())
    assert cfg.auth_enabled is False
    with TestClient(create_app(cfg)) as c:
        assert c.get("/capabilities").status_code == 401
        assert c.get("/capabilities", headers=_basic(USER, PASSWORD)).status_code == 200


# --------------------------------------------------------------------------- #
# Combined app — the static UI is the whole reason this middleware exists
# --------------------------------------------------------------------------- #

def test_static_ui_is_gated(tmp_path):
    app = create_combined_app(_config(tmp_path), _ui_dir(tmp_path))
    with TestClient(app) as c:
        assert c.get("/").status_code == 401
        assert c.get("/app.js").status_code == 401
        r = c.get("/", headers=_basic(USER, PASSWORD))
        assert r.status_code == 200
        assert "APPSECWATCH UI" in r.text


def test_combined_api_gated_and_state_crosses_the_mount(tmp_path):
    """The middleware runs on the PARENT and stamps request.state; the /api
    sub-app must see that stamp, or every API call would 401 despite a valid
    Basic login. (Starlette carries state in the ASGI scope across mounts —
    pinned here because the whole design leans on it.)"""
    app = create_combined_app(_config(tmp_path), _ui_dir(tmp_path))
    with TestClient(app) as c:
        assert c.get("/api/capabilities").status_code == 401
        r = c.get("/api/capabilities", headers=_basic(USER, PASSWORD))
        assert r.status_code == 200
        assert "capabilities" in r.json()


def test_combined_healthz_open(tmp_path):
    app = create_combined_app(_config(tmp_path), _ui_dir(tmp_path))
    with TestClient(app) as c:
        r = c.get("/api/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_combined_api_key_bypasses_prompt(tmp_path):
    app = create_combined_app(_config(tmp_path), _ui_dir(tmp_path))
    with TestClient(app) as c:
        r = c.get("/api/assets", headers={"Authorization": f"Bearer {API_KEY}"})
    assert r.status_code == 200


def test_report_link_query_param_still_works_through_the_gate(tmp_path):
    """`?api_key=` exists because <iframe>/<a> can't set headers. The middleware
    must honour it, else the report/executive links break behind the gate."""
    app = create_combined_app(_config(tmp_path), _ui_dir(tmp_path))
    with TestClient(app) as c:
        # 404 (no such scan) is the PASS here: it proves we got past auth to the
        # handler. A 401 would mean the gate ate the query-param credential.
        r = c.get(f"/api/scans/nope/report?api_key={API_KEY}")
    assert r.status_code == 404


def test_env_var_wiring(tmp_path, monkeypatch):
    """APPSECWATCH_BASIC_AUTH → ServerConfig, via the documented env name."""
    from appsecwatch.api.config import load_server_config

    monkeypatch.setenv("APPSECWATCH_BASIC_AUTH", f"{USER}:{PASSWORD}")
    monkeypatch.setenv("APPSECWATCH_API_KEYS", API_KEY)
    path = tmp_path / "server.yaml"
    path.write_text(json.dumps({"output_root": str(tmp_path / "runs")}))
    cfg = load_server_config(path)
    assert cfg.basic_auth_user == USER
    assert cfg.basic_auth_password == PASSWORD
    assert cfg.basic_auth_enabled is True
