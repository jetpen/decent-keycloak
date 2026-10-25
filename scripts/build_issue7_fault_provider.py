#!/usr/bin/env python3
"""Package only the test factory and its nested delegates, never JUnit tests."""
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FACTORY = 'org/decentwallet/keycloak/wallet/Issue7FaultInjectingSingleUseObjectProviderFactory'
SERVICE = 'META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory'


def main():
  classes = ROOT / 'target/test-classes'
  outer = classes / (FACTORY + '.class')
  if not outer.is_file():
    raise SystemExit('run Maven test-compile before packaging the Issue #7 test provider')
  selected = [outer, *sorted(classes.glob(FACTORY + '$*.class'))]
  output = ROOT / 'target/issue7-fault-provider.jar'
  with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in selected:
      archive.write(path, str(path.relative_to(classes)))
    archive.writestr(SERVICE, FACTORY.replace('/', '.') + '\n')
  print(output)


if __name__ == '__main__':
  main()
