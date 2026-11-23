"""Test-only relying party for offline OIDC Authorization Code + PKCE tests."""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import re
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class _NoRedirect(HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, new_url):
    return None


_LOCAL_HTTP = build_opener(ProxyHandler({}), _NoRedirect())


def _open_local(request: Request, timeout: int):
  return _LOCAL_HTTP.open(request, timeout=timeout)


@dataclass(frozen=True)
class FixtureConfig:
  """Issuer/client settings; redirect is derived from the loopback listener."""
  issuer: str
  client_id: str
  redirect_path: str = "/callback"
  session_ttl_seconds: int = 60

  def __post_init__(self):
    parts = urlsplit(self.issuer)
    if (parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "::1")
        or not parts.netloc or parts.query or parts.fragment):
      raise ValueError("test RP issuer must be an HTTP loopback URL")
    if (not self.client_id or len(self.client_id) > 128
        or not self.redirect_path.startswith("/") or self.redirect_path.startswith("//")
        or "?" in self.redirect_path or "#" in self.redirect_path):
      raise ValueError("invalid test RP configuration")
    if type(self.session_ttl_seconds) is not int or not 1 <= self.session_ttl_seconds <= 3600:
      raise ValueError("invalid test RP session lifetime")


class RPFixture:
  """Small HTTP fixture; all transaction/session state is bounded and memory-only."""
  def __init__(self, config: FixtureConfig):
    self.config = config
    self._lock = threading.RLock()
    self._transactions: dict[str, dict[str, object]] = {}
    self._sessions: dict[str, float] = {}
    self._server: ThreadingHTTPServer | None = None
    self._thread: threading.Thread | None = None

  @property
  def session_count(self) -> int:
    with self._lock:
      self._expire_sessions()
      return len(self._sessions)

  def start(self) -> ThreadingHTTPServer:
    if self._server is not None:
      raise RuntimeError("test RP fixture is already running")
    owner = self

    class Handler(BaseHTTPRequestHandler):
      server_version = "OfflineRPFixture"
      sys_version = ""

      def log_message(self, format, *args):
        # Deliberately discard request targets and remote-provided values.
        pass

      def do_GET(self):
        request_path = urlsplit(self.path).path
        if request_path == "/login":
          owner._login(self)
        elif request_path == owner.config.redirect_path:
          owner._callback(self)
        else:
          self._reject()

      def _reject(self):
        body = b"request rejected"
        self.send_response(400)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    self._server.daemon_threads = True
    self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
    self._thread.start()
    return self._server

  def close(self):
    if self._server is not None:
      self._server.shutdown()
      self._server.server_close()
      if self._thread is not None:
        self._thread.join(timeout=3)
      self._server = None
      self._thread = None
    with self._lock:
      self._transactions.clear()
      self._sessions.clear()

  def diagnostics(self) -> dict:
    """No values are emitted: only a fixed empty diagnostics object."""
    return {}

  def _redirect_uri(self) -> str:
    assert self._server is not None
    host, port = self._server.server_address
    return f"http://{host}:{port}{self.config.redirect_path}"

  def _issuer_metadata(self) -> dict:
    metadata_url = self.config.issuer.rstrip("/") + "/.well-known/openid-configuration"
    with _open_local(Request(metadata_url, headers={"Accept": "application/json"}), timeout=3) as response:
      if response.status != 200:
        raise ValueError("issuer metadata unavailable")
      metadata = json.loads(response.read(32769))
    if (not isinstance(metadata, dict) or metadata.get("issuer") != self.config.issuer
        or not all(isinstance(metadata.get(name), str) for name in
            ("authorization_endpoint", "token_endpoint", "jwks_uri"))):
      raise ValueError("issuer metadata invalid")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
      endpoint = urlsplit(metadata[name])
      issuer = urlsplit(self.config.issuer)
      if endpoint.scheme != "http" or endpoint.hostname != issuer.hostname or endpoint.port != issuer.port:
        raise ValueError("issuer endpoint outside configured loopback issuer")
    return metadata

  def _login(self, handler):
    if self._server is None:
      handler._reject()
      return
    try:
      metadata = self._issuer_metadata()
    except Exception:
      handler._reject()
      return
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(32)
    browser = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    transaction = {"nonce": nonce, "verifier": verifier, "browser": browser,
        "created": time.time()}
    with self._lock:
      self._expire_sessions()
      self._transactions[state] = transaction
      while len(self._transactions) > 128:
        del self._transactions[next(iter(self._transactions))]
    parameters = urlencode({"response_type": "code", "client_id": self.config.client_id,
        "redirect_uri": self._redirect_uri(), "scope": "openid", "state": state,
        "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
    handler.send_response(302)
    handler.send_header("Location", metadata["authorization_endpoint"] + "?" + parameters)
    handler.send_header("Set-Cookie", f"rp_browser={browser}; HttpOnly; SameSite=Lax; Path=/")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", "0")
    handler.end_headers()

  def _callback(self, handler):
    query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True)
    if set(query) != {"code", "state"} or any(len(values) != 1 or not values[0] for values in query.values()):
      handler._reject()
      return
    code, state = query["code"][0], query["state"][0]
    cookie = SimpleCookie()
    try:
      cookie.load(handler.headers.get("Cookie", ""))
    except Exception:
      handler._reject()
      return
    morsel = cookie.get("rp_browser")
    if morsel is None:
      handler._reject()
      return
    with self._lock:
      transaction = self._transactions.get(state)
      if (not transaction or not hmac.compare_digest(str(transaction["browser"]), morsel.value)
          or time.time() - float(transaction["created"]) > 300):
        handler._reject()
        return
      del self._transactions[state]
    try:
      metadata = self._issuer_metadata()
      token_response = self._exchange(metadata["token_endpoint"], code,
          str(transaction["verifier"]))
      claims = self._validate_id_token(str(token_response.get("id_token", "")),
          metadata["jwks_uri"], str(transaction["nonce"]))
      if not claims.get("sub"):
        raise ValueError("invalid ID token")
    except Exception:
      handler._reject()
      return
    with self._lock:
      self._expire_sessions()
      while len(self._sessions) >= 128:
        del self._sessions[next(iter(self._sessions))]
      self._sessions[secrets.token_urlsafe(32)] = time.time() + self.config.session_ttl_seconds
    body = b"authenticated"
    handler.send_response(200)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

  def _exchange(self, endpoint: str, code: str, verifier: str) -> dict:
    body = urlencode({"grant_type": "authorization_code", "code": code,
        "redirect_uri": self._redirect_uri(), "client_id": self.config.client_id,
        "code_verifier": verifier}).encode("ascii")
    request = Request(endpoint, data=body, headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, method="POST")
    with _open_local(request, timeout=3) as response:
      if response.status != 200:
        raise ValueError("token exchange failed")
      result = json.loads(response.read(32769))
    if not isinstance(result, dict):
      raise ValueError("token response invalid")
    return result

  def _validate_id_token(self, token: str, jwks_uri: str, expected_nonce: str) -> dict:
    pieces = token.split(".")
    if len(token) > 32768 or len(pieces) != 3 or not all(pieces):
      raise ValueError("invalid ID token")

    def decode(part):
      if re.fullmatch(r"[A-Za-z0-9_-]+", part) is None:
        raise ValueError("invalid ID token encoding")
      padded = part + "=" * (-len(part) % 4)
      return base64.b64decode(padded, altchars=b"-_", validate=True)

    def object_json(raw):
      def unique(items):
        result = {}
        for key, value in items:
          if key in result:
            raise ValueError("duplicate JSON member")
          result[key] = value
        return result
      value = json.loads(raw, object_pairs_hook=unique)
      if not isinstance(value, dict):
        raise ValueError("invalid JWT JSON")
      return value

    header = object_json(decode(pieces[0]))
    claims = object_json(decode(pieces[1]))
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
      raise ValueError("invalid ID token algorithm")
    with _open_local(Request(jwks_uri, headers={"Accept": "application/json"}), timeout=3) as response:
      if response.status != 200:
        raise ValueError("issuer keys unavailable")
      jwks = json.loads(response.read(65537))
    keys = [key for key in jwks.get("keys", []) if isinstance(key, dict)
        and key.get("kid") == header["kid"] and key.get("kty") == "RSA"
        and key.get("alg") == "RS256" and key.get("use") == "sig"
        and ("key_ops" not in key or "verify" in key.get("key_ops", []))]
    if len(keys) != 1:
      raise ValueError("issuer signing key is ambiguous")
    jwk = keys[0]
    modulus = int.from_bytes(decode(jwk["n"]), "big")
    exponent = int.from_bytes(decode(jwk["e"]), "big")
    if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
      raise ValueError("invalid issuer signing key")
    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    signature = decode(pieces[2])
    public_key.verify(signature, (pieces[0] + "." + pieces[1]).encode("ascii"),
        padding.PKCS1v15(), hashes.SHA256())
    now = int(time.time())
    exp, issued = claims.get("exp"), claims.get("iat")
    aud = claims.get("aud")
    audience_valid = (aud == self.config.client_id if isinstance(aud, str) else
        isinstance(aud, list) and len(aud) == 1 and type(aud[0]) is str
        and aud[0] == self.config.client_id)
    azp = claims.get("azp")
    # The loopback fake issuer shares this host clock; nbf has zero skew.
    if (claims.get("iss") != self.config.issuer or not audience_valid
        or ("azp" in claims and azp != self.config.client_id)
        or claims.get("nonce") != expected_nonce or not isinstance(claims.get("sub"), str)
        or type(exp) is not int or type(issued) is not int
        or exp <= now or exp > now + 3600 or issued > now + 60 or issued < now - 3600
        or ("nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > now))):
      raise ValueError("ID token claims invalid")
    return claims

  def _expire_sessions(self):
    now = time.time()
    self._sessions = {key: deadline for key, deadline in self._sessions.items() if deadline > now}


__all__ = ["FixtureConfig", "RPFixture"]
