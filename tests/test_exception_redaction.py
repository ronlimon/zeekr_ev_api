"""client must not put credentials into its exception messages.

These reach the log at ERROR through network._refresh_token, which logs the
message and then re-raises it, so no debug logging is needed for them to be
written. Every test here drives the real client method and inspects the
exception it raises — building the message in the test would only exercise
redact() and would pass with the fix reverted.
"""

import base64
import logging
import threading
from unittest.mock import MagicMock, patch

import pytest
from Crypto.PublicKey import RSA

from zeekr_ev_api import network
from zeekr_ev_api.client import ZeekrClient
from zeekr_ev_api.exceptions import AuthException, ZeekrException

TOKEN = "TOKENVALUE-super-secret"

# A throwaway key: the login flow RSA-encrypts the password before sending.
PUBLIC_KEY = base64.b64encode(RSA.generate(1024).publickey().export_key("DER")).decode()


@pytest.fixture
def client():
    c = ZeekrClient(
        username="testuser",
        password="testpassword",
        hmac_access_key="key",
        hmac_secret_key="secret",
        password_public_key=PUBLIC_KEY,
        prod_secret="prodsecret",
    )
    c.session = MagicMock()
    c.logger = MagicMock()
    return c


def test_bearer_login_failure_does_not_leak_the_response(client):
    block = {"success": False, "code": "AUTH_401", "data": {"accessToken": TOKEN}}
    with patch("zeekr_ev_api.network.appSignedPost", return_value=block):
        with pytest.raises(AuthException) as excinfo:
            client._bearer_login("tsp-code")
    assert TOKEN not in str(excinfo.value)
    assert "AUTH_401" in str(excinfo.value), "the diagnostic part must survive"


def test_missing_bearer_token_does_not_leak_the_data_block(client):
    block = {"success": True, "data": {"refreshToken": TOKEN, "expiresIn": 7200}}
    with patch("zeekr_ev_api.network.appSignedPost", return_value=block):
        with pytest.raises(AuthException) as excinfo:
            client._bearer_login("tsp-code")
    assert TOKEN not in str(excinfo.value)
    assert "7200" in str(excinfo.value)


def test_tsp_code_failure_does_not_leak_the_block(client):
    block = {"success": False, "msg": "denied", "data": {"tokenValue": TOKEN}}
    with patch("zeekr_ev_api.network.customGet", return_value=block):
        with pytest.raises(ZeekrException) as excinfo:
            client._get_tsp_code()
    assert TOKEN not in str(excinfo.value)
    assert "denied" in str(excinfo.value)


def test_missing_tsp_code_does_not_leak_the_block(client):
    block = {"success": True, "data": {"loginId": "L-1", "accessToken": TOKEN}}
    with patch("zeekr_ev_api.network.customGet", return_value=block):
        with pytest.raises(ZeekrException) as excinfo:
            client._get_tsp_code()
    assert TOKEN not in str(excinfo.value)


def test_unknown_token_type_reports_the_type_not_the_block(client):
    """That site wants the type; redacting the dict would hide the very answer."""
    resp = MagicMock()
    resp.json.return_value = {
        "success": True,
        "data": {"tokenName": "Bearer", "tokenValue": TOKEN},
    }
    client.session.send.return_value = resp
    with pytest.raises(AuthException) as excinfo:
        client._do_login_request()
    assert TOKEN not in str(excinfo.value)
    assert "Bearer" in str(excinfo.value), "the token type is the point of this error"


def test_login_failure_does_not_leak_the_response(client):
    resp = MagicMock()
    resp.json.return_value = {"success": False, "msg": "bad password", "data": {"pwd": TOKEN}}
    client.session.send.return_value = resp
    with pytest.raises(AuthException) as excinfo:
        client._do_login_request()
    assert TOKEN not in str(excinfo.value)
    assert "bad password" in str(excinfo.value)


def test_refresh_failure_does_not_log_a_credential(caplog, client):
    """The amplifier: _refresh_token logs at ERROR and re-raises the message."""
    caplog.set_level(logging.ERROR)
    client.logger = logging.getLogger("zeekr_ev_api.network")
    client.bearer_token = "expired"
    # A real lock: MagicMock.__exit__ returns something truthy and would swallow
    # the exception being asserted on.
    client.auth_lock = threading.Lock()
    block = {"success": True, "data": {"refreshToken": TOKEN, "expiresIn": 7200}}

    with patch("zeekr_ev_api.network.appSignedPost", return_value=block):
        with patch.object(ZeekrClient, "login", lambda self, relogin=False: self._bearer_login("c")):
            with pytest.raises(AuthException) as excinfo:
                network._refresh_token(client, "expired")

    assert TOKEN not in caplog.text
    assert TOKEN not in str(excinfo.value), "the re-raised message reaches the consumer too"
    assert "7200" in caplog.text, "the non-secret part should stay diagnosable"
