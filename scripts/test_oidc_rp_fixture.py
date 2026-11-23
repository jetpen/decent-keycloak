"""Offline contract tests for the test-only OIDC relying-party fixture."""
from __future__ import annotations

import base64
from contextlib import redirect_stderr
import hashlib
import http.client
import io
import json
import os
import secrets
import sys
import threading
import time
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from scripts.oidc_rp_fixture import FixtureConfig, RPFixture


def b64url(raw: bytes) -> str:
  return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwt_part(value: object) -> str:
  return b64url(json.dumps(value, separators=(",", ":")).encode())


class FakeIssuer:
  """Loopback-only OIDC issuer which validates the original PKCE verifier."""
  def __init__(self):
    self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    self.kid = "fixture-signing-key"
    self.issuer = "http://127.0.0.1:0/issuer"
    self.client_id = "test-rp-client"
    self.redirect_uri = ""
    self.challenge_by_code: dict[str, str] = {}
    self.codes: set[str] = set()
    self.tokens: dict[str, str] = {}
    self.token_requests: list[dict[str, str]] = []
    self.duplicate_jwks = False
    self.jwks_reads = 0
    outer = self

    class Handler(BaseHTTPRequestHandler):
      def log_message(self, *_args):
        pass

      def do_GET(self):
        path = urlsplit(self.path)
        if path.path == "/issuer/.well-known/openid-configuration":
          self._json({"issuer": outer.issuer.rstrip("/"),
              "authorization_endpoint": outer.base + "/authorize",
              "token_endpoint": outer.base + "/token",
              "jwks_uri": outer.base + "/jwks"})
        elif path.path == "/jwks":
          outer.jwks_reads += 1
          n = outer.key.public_key().public_numbers().n
          def integer(value):
            return value.to_bytes((value.bit_length() + 7) // 8, "big")
          signing_key = {"kty": "RSA", "use": "sig", "alg": "RS256",
              "kid": outer.kid, "n": b64url(integer(n)), "e": b64url(integer(65537))}
          keys = [signing_key, signing_key] if outer.duplicate_jwks else [signing_key]
          self._json({"keys": keys})
        elif path.path == "/authorize":
          q = parse_qs(path.query, keep_blank_values=True, strict_parsing=True)
          if (q.get("client_id") != [outer.client_id]
              or q.get("redirect_uri") != [outer.redirect_uri]
              or q.get("response_type") != ["code"]
              or q.get("scope") != ["openid"]
              or q.get("code_challenge_method") != ["S256"]
              or len(q.get("nonce", [])) != 1 or not q["nonce"][0]):
            self.send_error(400)
            return
          code = secrets.token_urlsafe(24)
          outer.codes.add(code)
          outer.challenge_by_code[code] = q["code_challenge"][0]
          outer.nonce_by_code[code] = q["nonce"][0]
          target = outer.redirect_uri + "?" + urlencode({"code": code, "state": q["state"][0]})
          self.send_response(302)
          self.send_header("Location", target)
          self.end_headers()
        else:
          self.send_error(404)

      def do_POST(self):
        if self.path != "/token":
          self.send_error(404)
          return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        values = parse_qs(body.decode(), keep_blank_values=True, strict_parsing=True)
        data = {key: vals[0] for key, vals in values.items() if len(vals) == 1}
        outer.token_requests.append(data)
        code = data.get("code", "")
        verifier = data.get("code_verifier", "")
        if (code not in outer.codes or code not in outer.challenge_by_code
            or data.get("grant_type") != "authorization_code"
            or data.get("client_id") != outer.client_id
            or data.get("redirect_uri") != outer.redirect_uri
            or b64url(hashlib.sha256(verifier.encode()).digest()) != outer.challenge_by_code[code]):
          self.send_error(400)
          return
        outer.codes.remove(code)
        outer.challenge_by_code.pop(code, None)
        access_token = secrets.token_urlsafe(24)
        nonce = outer.nonce_by_code.pop(code, "")
        token = outer.make_token(nonce)
        outer.tokens[access_token] = token
        self._json({"access_token": access_token, "id_token": token, "token_type": "Bearer"})

      def _json(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    self.nonce_by_code: dict[str, str] = {}
    self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    self.base = f"http://127.0.0.1:{self.httpd.server_port}"
    self.issuer = self.base + "/issuer"
    self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
    self.thread.start()

  def make_token(self, nonce: str, *, claims=None, key=None, kid=None, alg="RS256"):
    now = int(time.time())
    payload = {"iss": self.issuer, "sub": "fixture-subject", "aud": self.client_id,
        "iat": now, "exp": now + 300, "nonce": nonce}
    payload.update(claims or {})
    header = {"alg": alg, "kid": kid or self.kid, "typ": "JWT"}
    signing_input = (jwt_part(header) + "." + jwt_part(payload)).encode("ascii")
    signer = key or self.key
    signature = signer.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode() + "." + b64url(signature)

  def close(self):
    self.httpd.shutdown()
    self.httpd.server_close()
    self.thread.join(timeout=3)


class RPFixtureContractTest(unittest.TestCase):
  def setUp(self):
    self.issuer = FakeIssuer()
    self.fixture = RPFixture(FixtureConfig(
        issuer=self.issuer.issuer, client_id=self.issuer.client_id,
        redirect_path="/callback", session_ttl_seconds=60))
    self.server = self.fixture.start()
    self.issuer.redirect_uri = f"http://127.0.0.1:{self.server.server_port}/callback"

  def tearDown(self):
    self.fixture.close()
    self.issuer.close()

  def request(self, method, path, *, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    conn.close()
    return result

  def start_login(self):
    status, headers, body = self.request("GET", "/login")
    self.assertEqual(302, status)
    self.assertEqual(b"", body)
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    location = headers["Location"]
    query = parse_qs(urlsplit(location).query, keep_blank_values=True)
    self.assertEqual([self.issuer.client_id], query["client_id"])
    self.assertEqual([self.issuer.redirect_uri], query["redirect_uri"])
    self.assertEqual(["code"], query["response_type"])
    self.assertEqual(["openid"], query["scope"])
    self.assertEqual(["S256"], query["code_challenge_method"])
    self.assertEqual(43, len(query["code_challenge"][0]))
    self.assertTrue(query["state"][0])
    self.assertTrue(query["nonce"][0])
    return cookie, location, query["state"][0], query["nonce"][0]

  def authorize_and_callback(self, cookie, location, state, *, callback_mutation=None):
    issuer_conn = http.client.HTTPConnection("127.0.0.1", self.issuer.httpd.server_port, timeout=3)
    issuer_conn.request("GET", urlsplit(location).path + "?" + urlsplit(location).query)
    response = issuer_conn.getresponse()
    self.assertEqual(302, response.status)
    callback = response.getheader("Location")
    issuer_conn.close()
    callback_parts = urlsplit(callback)
    callback_query = parse_qs(callback_parts.query, keep_blank_values=True)
    code = callback_query["code"][0]
    if callback_mutation:
      callback = callback_mutation(callback, callback_query)
    return self.request("GET", callback_parts.path + ("?" + urlsplit(callback).query if "?" in callback else ""),
        headers={"Cookie": cookie})

  def test_fixture_and_fake_issuer_bind_only_to_loopback(self):
    self.assertEqual("127.0.0.1", self.server.server_address[0])
    self.assertEqual("127.0.0.1", self.issuer.httpd.server_address[0])
    with self.assertRaises(ValueError):
      FixtureConfig("https://idp.example/realm", self.issuer.client_id)
    with self.assertRaises(ValueError):
      FixtureConfig("http://192.0.2.10/realm", self.issuer.client_id)
    with self.assertRaises(ValueError):
      FixtureConfig(self.issuer.issuer, self.issuer.client_id, session_ttl_seconds=3601)
    with self.assertRaises(ValueError):
      FixtureConfig(self.issuer.issuer, self.issuer.client_id, session_ttl_seconds=0)

  def test_authorization_code_pkce_and_validated_token_create_only_ephemeral_session(self):
    cookie, location, state, nonce = self.start_login()
    status, headers, body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)
    self.assertEqual(b"authenticated", body)
    self.assertNotIn("Set-Cookie", headers)
    self.assertEqual(1, len(self.issuer.token_requests))
    sent = self.issuer.token_requests[0]
    self.assertEqual("authorization_code", sent["grant_type"])
    self.assertTrue(sent["code_verifier"])
    self.assertNotIn(sent["code_verifier"], cookie)
    self.assertNotIn("id_token", body.decode())
    self.assertEqual(1, self.fixture.session_count)

  def _complete_with_claims(self, claims):
    cookie, location, state, _nonce = self.start_login()
    original = self.issuer.make_token
    self.issuer.make_token = lambda nonce: _make_default_token(self.issuer, nonce, claims)
    try:
      status, _headers, body = self.authorize_and_callback(cookie, location, state)
      return status, body
    finally:
      self.issuer.make_token = original

  def test_singleton_array_audience_is_accepted_but_untrusted_or_mismatched_audiences_are_rejected(self):
    valid = self._complete_with_claims({"aud": [self.issuer.client_id]})
    self.assertEqual((200, b"authenticated"), valid)
    prior_sessions = self.fixture.session_count
    for claims in (
        {"aud": self.issuer.client_id, "azp": "other-client"},
        {"aud": "other-client"},
        {"aud": [self.issuer.client_id, "untrusted-client"]},
        {"aud": []},
        {"aud": [self.issuer.client_id, self.issuer.client_id]},
        {"aud": [self.issuer.client_id, 7]},
    ):
      with self.subTest(claims=claims):
        status, body = self._complete_with_claims(claims)
        self.assertEqual((400, b"request rejected"), (status, body))
        self.assertEqual(prior_sessions, self.fixture.session_count)

  def test_nbf_uses_zero_skew_and_accepts_exact_current_time(self):
    original_time = time.time
    try:
      fixed_now = int(original_time())
      time.time = lambda: fixed_now
      accepted = self._complete_with_claims({"nbf": fixed_now})
      self.assertEqual((200, b"authenticated"), accepted)
      prior_sessions = self.fixture.session_count
      rejected = self._complete_with_claims({"nbf": fixed_now + 1})
      self.assertEqual((400, b"request rejected"), rejected)
      self.assertEqual(prior_sessions, self.fixture.session_count)
      for bad_nbf in (True, "123", 1.5):
        with self.subTest(nbf=bad_nbf):
          self.assertEqual((400, b"request rejected"), self._complete_with_claims({"nbf": bad_nbf}))
    finally:
      time.time = original_time

  def test_public_login_bypasses_environment_proxy_for_loopback_issuer(self):
    seen = []
    class ProxyHandler(BaseHTTPRequestHandler):
      def log_message(self, *_args):
        pass
      def do_GET(self):
        seen.append(self.path)
        self.send_error(502)
      def do_POST(self):
        seen.append(self.path)
        self.send_error(502)
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    env_names = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy")
    old_env = {name: os.environ.get(name) for name in env_names}
    try:
      for name in env_names:
        os.environ.pop(name, None)
      proxy_url = f"http://127.0.0.1:{proxy.server_port}"
      os.environ["HTTP_PROXY"] = proxy_url
      os.environ["http_proxy"] = proxy_url
      import importlib
      import scripts.oidc_rp_fixture as rp_module
      prior_opener = rp_module._LOCAL_HTTP
      try:
        importlib.reload(rp_module)
        status, headers, _body = self.request("GET", "/login")
        self.assertEqual(302, status)
        self.assertTrue(headers["Location"].startswith(self.issuer.base + "/authorize?"))
        self.assertEqual([], seen)
      finally:
        rp_module._LOCAL_HTTP = prior_opener
    finally:
      for name, value in old_env.items():
        if value is None:
          os.environ.pop(name, None)
        else:
          os.environ[name] = value
      proxy.shutdown()
      proxy.server_close()
      proxy_thread.join(timeout=3)

  def test_authenticated_outcome_does_not_create_disk_artifacts(self):
    original_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="rp-fixture-", dir=os.environ.get("TMPDIR")) as temporary:
      os.chdir(temporary)
      try:
        cookie, location, state, nonce = self.start_login()
        status, _headers, _body = self.authorize_and_callback(cookie, location, state)
        self.assertEqual(200, status)
        self.assertEqual(1, self.fixture.session_count)
        self.assertEqual([], list(Path(temporary).iterdir()))
      finally:
        os.chdir(original_cwd)

  def test_bad_nonce_issuer_audience_signature_and_expiry_do_not_create_sessions(self):
    cookie, location, state, nonce = self.start_login()
    status, _headers, _body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)  # valid control reaches and passes ID-token validation
    prior_sessions = self.fixture.session_count
    now = int(time.time())
    cases = [
        ("nonce", {"nonce": "wrong-nonce"}, None),
        ("issuer", {"iss": "https://wrong.invalid"}, None),
        ("audience", {"aud": "other-client"}, None),
        ("expiry", {"exp": now - 1}, None),
        ("issued-in-future", {"iat": now + 120}, None),
        ("not-yet-valid", {"nbf": now + 120}, None),
        ("excessive-lifetime", {"exp": now + 7200}, None),
        ("signature", {}, rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ]
    for label, claims, signing_key in cases:
      with self.subTest(label=label):
        cookie, location, state, nonce = self.start_login()
        requests_before = len(self.issuer.token_requests)
        keys_before = self.issuer.jwks_reads
        if label != "signature":
          self.issuer.make_token = lambda expected, c=claims: _make_default_token(self.issuer, expected, c)
        else:
          self.issuer.make_token = lambda expected, k=signing_key: _make_default_token(self.issuer, expected, {}, k)
        try:
          status, _headers, body = self.authorize_and_callback(cookie, location, state)
          self.assertEqual(400, status)
          self.assertEqual(b"request rejected", body)
          self.assertEqual(requests_before + 1, len(self.issuer.token_requests))
          self.assertEqual(keys_before + 1, self.issuer.jwks_reads)
          self.assertEqual(prior_sessions, self.fixture.session_count)
        finally:
          self.issuer.make_token = FakeIssuer.make_token.__get__(self.issuer)

  def test_state_cookie_mismatch_missing_duplicate_unknown_and_replay_are_rejected(self):
    cookie, location, state, nonce = self.start_login()
    token_attempts_before = len(self.issuer.token_requests)
    status, _headers, _body = self.authorize_and_callback(cookie, location, state,
        callback_mutation=lambda url, q: url.replace("state=" + state, "state=wrong"))
    self.assertEqual(400, status)
    self.assertEqual(token_attempts_before, len(self.issuer.token_requests))
    self.assertEqual(0, self.fixture.session_count)

    cookie, location, state, nonce = self.start_login()
    status, headers, body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)
    callback = urlsplit(headers.get("Location", ""))
    self.assertEqual(1, self.fixture.session_count)
    # The already-consumed callback cannot be replayed, even with the same browser cookie.
    auth_conn = http.client.HTTPConnection("127.0.0.1", self.issuer.httpd.server_port, timeout=3)
    auth_conn.request("GET", urlsplit(location).path + "?" + urlsplit(location).query)
    response = auth_conn.getresponse()
    replay_url = response.getheader("Location")
    auth_conn.close()
    self.assertNotEqual("", replay_url)
    status, _headers, _body = self.request("GET", urlsplit(replay_url).path + "?" + urlsplit(replay_url).query,
        headers={"Cookie": cookie})
    self.assertEqual(400, status)
    self.assertEqual(1, self.fixture.session_count)

  def test_missing_duplicate_and_unexpected_callback_parameters_fail_closed(self):
    cookie, location, _state, nonce = self.start_login()
    conn = http.client.HTTPConnection("127.0.0.1", self.issuer.httpd.server_port, timeout=3)
    conn.request("GET", urlsplit(location).path + "?" + urlsplit(location).query)
    response = conn.getresponse()
    callback = response.getheader("Location")
    conn.close()
    parts = urlsplit(callback)
    callback_values = parse_qs(parts.query)

    token_attempts_before = len(self.issuer.token_requests)
    for malformed in (parts.path + "?code=", parts.path + "?" + parts.query + "&state=duplicate",
        parts.path + "?" + parts.query + "&unexpected=x"):
      with self.subTest(callback=malformed):
        status, _headers, body = self.request("GET", malformed, headers={"Cookie": cookie})
        self.assertEqual(400, status)
        self.assertEqual(b"request rejected", body)
        self.assertEqual(token_attempts_before, len(self.issuer.token_requests))
        self.assertEqual(0, self.fixture.session_count)
    # A malformed attempt does not consume the legitimate active transaction.
    status, _headers, _body = self.request("GET", parts.path + "?" + parts.query,
        headers={"Cookie": cookie})
    self.assertEqual(200, status)
    self.assertEqual(1, self.fixture.session_count)

  def test_fresh_login_uses_distinct_state_nonce_challenge_and_browser_cookie(self):
    cookie1, location1, state1, nonce1 = self.start_login()
    cookie2, location2, state2, nonce2 = self.start_login()
    query1 = parse_qs(urlsplit(location1).query)
    query2 = parse_qs(urlsplit(location2).query)
    self.assertNotEqual(state1, state2)
    self.assertNotEqual(nonce1, nonce2)
    self.assertNotEqual(query1["code_challenge"], query2["code_challenge"])
    self.assertNotEqual(cookie1, cookie2)

  def test_malformed_id_token_and_ambiguous_jwks_do_not_create_sessions(self):
    cookie, location, state, nonce = self.start_login()
    status, _headers, _body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)  # same issuer/key/token path is eligible
    prior_sessions = self.fixture.session_count
    prior_requests = len(self.issuer.token_requests)
    cookie, location, state, nonce = self.start_login()
    original = self.issuer.make_token
    self.issuer.make_token = lambda _nonce, **_kwargs: "malformed-token"
    try:
      status, _headers, _body = self.authorize_and_callback(cookie, location, state)
      self.assertEqual(400, status)
      self.assertEqual(prior_requests + 1, len(self.issuer.token_requests))
      self.assertEqual(prior_sessions, self.fixture.session_count)
    finally:
      self.issuer.make_token = original

    cookie, location, state, nonce = self.start_login()
    self.issuer.make_token = lambda token_nonce: original(token_nonce, alg="none")
    try:
      status, _headers, _body = self.authorize_and_callback(cookie, location, state)
      self.assertEqual(400, status)
      self.assertEqual(prior_requests + 2, len(self.issuer.token_requests))
      self.assertEqual(prior_sessions, self.fixture.session_count)
    finally:
      self.issuer.make_token = original

    self.issuer.duplicate_jwks = True
    cookie, location, state, nonce = self.start_login()
    status, _headers, _body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(400, status)
    self.assertEqual(prior_requests + 3, len(self.issuer.token_requests))
    self.assertEqual(prior_sessions, self.fixture.session_count)

  def test_cookie_and_callback_responses_never_disclose_protocol_secrets(self):
    cookie, location, state, nonce = self.start_login()
    self.assertNotIn(state, cookie)
    self.assertNotIn(nonce, cookie)
    status, headers, body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)
    token_request = self.issuer.token_requests[0]
    response_secrets = [state, nonce, cookie.split("=", 1)[1], "code_verifier",
        token_request["code"], token_request["code_verifier"], *self.issuer.tokens.keys(), *self.issuer.tokens.values()]
    for marker in response_secrets:
      self.assertNotIn(marker.encode(), body)
      for name, value in headers.items():
        self.assertNotIn(marker, name + value)
    self.assertEqual({}, self.fixture.diagnostics())

  def test_bad_token_errors_and_stderr_do_not_include_claim_markers(self):
    cookie, location, state, nonce = self.start_login()
    status, _headers, _body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)  # positive control reaches successful session recording
    prior_sessions = self.fixture.session_count
    marker = "fixture-private-claim-marker-982173"
    cookie, location, state, nonce = self.start_login()
    self.issuer.make_token = lambda expected: _make_default_token(
        self.issuer, expected, {"iss": "https://wrong.invalid", "sub": marker})
    logs = io.StringIO()
    try:
      with redirect_stderr(logs):
        status, _headers, body = self.authorize_and_callback(cookie, location, state)
      self.assertEqual(400, status)
      self.assertEqual(b"request rejected", body)
      self.assertNotIn(marker, logs.getvalue())
      self.assertNotIn(marker, repr(self.fixture.diagnostics()))
      self.assertEqual(prior_sessions, self.fixture.session_count)
    finally:
      self.issuer.make_token = FakeIssuer.make_token.__get__(self.issuer)

  def test_second_browser_cookie_and_unknown_transaction_cannot_consume_state(self):
    cookie, location, state, nonce = self.start_login()
    issuer_conn = http.client.HTTPConnection("127.0.0.1", self.issuer.httpd.server_port, timeout=3)
    issuer_conn.request("GET", urlsplit(location).path + "?" + urlsplit(location).query)
    response = issuer_conn.getresponse()
    callback = response.getheader("Location") or ""
    issuer_conn.close()
    callback_query = parse_qs(urlsplit(callback).query)

    status, _headers, _body = self.request("GET", urlsplit(callback).path + "?" + urlsplit(callback).query,
        headers={"Cookie": "rp_browser=unknown"})
    self.assertEqual(400, status)
    self.assertEqual(0, len(self.issuer.token_requests))
    self.assertEqual(0, self.fixture.session_count)
    status, _headers, body = self.request("GET", urlsplit(callback).path + "?" + urlsplit(callback).query,
        headers={"Cookie": cookie})
    self.assertEqual(200, status)
    self.assertEqual(b"authenticated", body)
    self.assertEqual(1, len(self.issuer.token_requests))
    self.assertEqual(1, self.fixture.session_count)

  def test_token_request_uses_original_verifier_and_fake_issuer_rejects_reuse(self):
    cookie, location, state, nonce = self.start_login()
    status, _headers, _body = self.authorize_and_callback(cookie, location, state)
    self.assertEqual(200, status)
    original = self.issuer.token_requests[0]
    self.assertEqual("authorization_code", original["grant_type"])
    self.assertEqual(self.issuer.redirect_uri, original["redirect_uri"])
    self.assertEqual(self.issuer.client_id, original["client_id"])
    self.assertEqual(43, len(original["code_verifier"]))
    status, _headers, _body = self.issuer_token_replay(original)
    self.assertEqual(400, status)  # consumed code cannot be used twice

    _cookie, authorize_url, _state, _nonce = self.start_login()
    conn = http.client.HTTPConnection("127.0.0.1", self.issuer.httpd.server_port, timeout=3)
    conn.request("GET", urlsplit(authorize_url).path + "?" + urlsplit(authorize_url).query)
    response = conn.getresponse()
    callback = response.getheader("Location")
    conn.close()
    code = parse_qs(urlsplit(callback).query)["code"][0]
    fields = dict(original, code=code)
    for altered in (dict(fields, code_verifier="wrong-verifier"),
        {key: value for key, value in fields.items() if key != "code_verifier"}):
      status, _headers, _body = self.issuer_token_replay(altered)
      self.assertEqual(400, status)

    cookie, location, state, nonce = self.start_login()
    status, _headers, body = self.authorize_and_callback(cookie, location, state,
        callback_mutation=lambda url, _q: url.replace("code=", "code=not-issued-"))
    self.assertEqual(400, status)
    self.assertEqual(b"request rejected", body)
    self.assertEqual(1, self.fixture.session_count)

  def issuer_token_replay(self, fields):
    conn = http.client.HTTPConnection("127.0.0.1", self.issuer.httpd.server_port, timeout=3)
    conn.request("POST", "/token", body=urlencode(fields), headers={"Content-Type": "application/x-www-form-urlencoded"})
    response = conn.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    conn.close()
    return result


def _make_default_token(issuer, nonce, claims, key=None):
  return FakeIssuer.make_token(issuer, nonce, claims=claims, key=key)


if __name__ == "__main__":
  unittest.main()
