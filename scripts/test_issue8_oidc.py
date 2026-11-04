import sys
import unittest
from pathlib import Path

from joserfc import jwt
from joserfc.jwk import RSAKey

sys.path.insert(0, str(Path(__file__).parent))
import wallet_login_live_e2e as live  # noqa: E402

class Issue8OidcAcceptanceTest(unittest.TestCase):

  def test_live_id_token_validation_uses_authlib_openid_connect_claim_validation(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def verify_id_token(')
    end = source.index('\ndef wallet_transport_log_categories', start)
    body = source[start:end]

    self.assertIn('CodeIDToken', body)
    self.assertIn('jwt.decode', body)
    self.assertNotIn("'openssl', 'dgst'", body)
    self.assertIn("'iss': {'value': expected_issuer}", body)
    self.assertIn("'aud': {'values': [expected_audience]}", body)
    self.assertIn("'nonce': {'value': expected_nonce}", body)

  @classmethod
  def setUpClass(cls):
    cls.key = RSAKey.generate_key(2048, {
        'kid': 'issue8-test-key', 'use': 'sig', 'alg': 'RS256'})
    cls.jwks = {'keys': [cls.key.as_dict(is_private=False)]}
    cls.now = int(__import__('time').time())
    cls.issuer = 'https://idp.example/realms/test'
    cls.audience = 'issue8-rp-client'
    cls.nonce = 'nonce-for-one-oidc-request'

  def _token(self, overrides=None, *, key=None, header=None):
    claims = {
        'iss': self.issuer, 'sub': 'opaque-keycloak-subject',
        'aud': self.audience, 'exp': self.now + 300,
        'iat': self.now, 'nonce': self.nonce,
    }
    claims.update(overrides or {})
    signer = key or self.key
    jose_header = {'alg': 'RS256', 'kid': 'issue8-test-key'}
    jose_header.update(header or {})
    return jwt.encode(jose_header, claims, signer, algorithms=['RS256'])

  class FakeClient:
    def __init__(self, jwks):
      self.jwks = jwks

    def request(self, method, path):
      if method != 'GET' or not path.endswith('/protocol/openid-connect/certs'):
        raise AssertionError('unexpected OIDC request')
      import json
      return 200, {}, json.dumps(self.jwks).encode()

  def _verify(self, token, *, jwks=None, issuer=None, audience=None, nonce=None):
    return live.verify_id_token(
        self.FakeClient(jwks or self.jwks), token,
        issuer or self.issuer, audience or self.audience, nonce or self.nonce)

  def test_valid_signed_id_token_requires_expected_oidc_claims(self):
    claims = self._verify(self._token())

    self.assertEqual(self.issuer, claims['iss'])
    self.assertEqual(self.audience, claims['aud'])
    self.assertEqual(self.nonce, claims['nonce'])
    self.assertEqual('opaque-keycloak-subject', claims['sub'])

  def test_id_token_rejects_wrong_issuer_audience_expiry_and_nonce(self):
    invalid = (
        ({'iss': 'https://attacker.example/realms/test'}, self.issuer, self.audience, self.nonce),
        ({'aud': 'another-client'}, self.issuer, self.audience, self.nonce),
        ({'exp': self.now - 1}, self.issuer, self.audience, self.nonce),
        ({'nonce': 'another-request'}, self.issuer, self.audience, self.nonce),
    )
    for claims, issuer, audience, nonce in invalid:
      with self.subTest(claims=claims):
        with self.assertRaises(ValueError):
          self._verify(self._token(claims), issuer=issuer, audience=audience, nonce=nonce)

  def test_id_token_rejects_wrong_signature_and_non_rs256_algorithm(self):
    other_key = RSAKey.generate_key(2048, {
        'kid': 'foreign-key', 'use': 'sig', 'alg': 'RS256'})
    wrong_signature = self._token(key=other_key, header={'kid': 'issue8-test-key'})
    with self.assertRaises(ValueError):
      self._verify(wrong_signature)

    import base64
    import json
    header = base64.urlsafe_b64encode(json.dumps({
        'alg': 'none', 'kid': 'issue8-test-key'}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(b'{}').decode().rstrip('=')
    disallowed = header + '.' + payload + '.'
    with self.assertRaises(RuntimeError):
      self._verify(disallowed)

  def test_id_token_rejects_ambiguous_jwks_signing_key(self):
    duplicate = {'keys': [self.jwks['keys'][0], self.jwks['keys'][0]]}

    with self.assertRaises(RuntimeError):
      self._verify(self._token(), jwks=duplicate)
