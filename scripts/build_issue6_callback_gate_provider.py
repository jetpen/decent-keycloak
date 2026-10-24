#!/usr/bin/env python3
"""Package the test-only Issue #6 callback-gate provider after Maven test-compile."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
classes = root / "target/test-classes"
class_prefix = "org/decentwallet/keycloak/issue6test/Issue6PostConsumeCallbackGateFailureProviderFactory"
class_file = classes / (class_prefix + ".class")
class_files = [class_file, *sorted(classes.glob(class_prefix + "$*.class"))]
service_path = "META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory"
service_content = ("org.decentwallet.keycloak.issue6test."
    "Issue6PostConsumeCallbackGateFailureProviderFactory\n")
output = root / "target/issue6-postconsume-callback-gate-failure-provider.jar"
if not class_file.is_file():
  raise SystemExit("run mvn -DskipTests test-compile before packaging the Issue #6 callback-gate provider")
output.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as jar:
  for provider_class in class_files:
    jar.write(provider_class, provider_class.relative_to(classes).as_posix())
  jar.writestr(service_path, service_content)
print(output)
