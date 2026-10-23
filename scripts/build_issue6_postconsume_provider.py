#!/usr/bin/env python3
"""Package the test-only Issue #6 provider after Maven test-compile."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
classes = root / "target/test-classes"
class_file = classes / "org/decentwallet/keycloak/issue6test/Issue6PostConsumeReceiptFailureProviderFactory.class"
service_file = classes / "META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory"
output = root / "target/issue6-postconsume-receipt-failure-provider.jar"
if not class_file.is_file() or not service_file.is_file():
  raise SystemExit("run mvn -DskipTests test-compile before packaging the Issue #6 test provider")
output.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as jar:
  jar.write(class_file, class_file.relative_to(classes).as_posix())
  jar.write(service_file, service_file.relative_to(classes).as_posix())
print(output)
