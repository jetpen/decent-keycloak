import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class SelfContainedResolverRuntimeTest(unittest.TestCase):
  def test_runtime_sources_are_pinned_to_immutable_revisions(self):
    lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    self.assertEqual({'identity', 'registry'}, set(lock['sources']))
    for source in lock['sources'].values():
      self.assertRegex(source['commit'], re.compile(r'^[0-9a-f]{40}$'))
      self.assertTrue(source['url'].startswith('https://github.com/'))
      self.assertTrue(source['requirements_lock'])

  def test_container_packages_resolver_and_gmp_without_host_mounts(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertIn('resolver-runtime.lock.json', dockerfile)
    self.assertIn('libgmp.so.10', dockerfile)
    self.assertIn('decent-identity', dockerfile)
    self.assertNotRegex(dockerfile, r'(?i)(/home/|/projects/|\.venv)')
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertNotIn("'--volume', f'{IDENTITY_VENV}:", harness)
    self.assertNotIn("'--volume', f'{REGISTRY_VENV}:", harness)
    self.assertNotIn("'--volume', f'{IDENTITY_SOURCE}:", harness)

  def test_existing_bounded_adapter_still_invokes_exact_identity_get(self):
    resolver = (ROOT / 'src/main/java/org/decentwallet/keycloak/wallet/ProcessIdentityResolver.java').read_text()
    self.assertIn('command.add("get")', resolver)
    self.assertIn('TIMEOUT_SECONDS = 10', resolver)
    self.assertIn('isConfirmedIdentityNotFound(outputText)', resolver)


if __name__ == '__main__':
  unittest.main()
