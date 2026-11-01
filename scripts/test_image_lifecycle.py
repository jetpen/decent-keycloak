"""Tests for repository-owned local image retention and cleanup."""

import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from scripts import image_lifecycle
from scripts import lifecycle

TEST_REPOSITORY_LABELS = {**image_lifecycle.REPOSITORY_LABELS,
    "io.decent.image.role": "wallet-provider"}


class ImageLifecycleTest(unittest.TestCase):
  def test_inventory_filters_exact_repository_and_component_labels_before_inspection(self):
    image_id = "sha256:" + "a" * 64
    metadata = {"Id": image_id, "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    with mock.patch.object(image_lifecycle, "_run", return_value=subprocess.CompletedProcess(
        [], 0, image_id + "\n", "")) as run, \
        mock.patch.object(image_lifecycle, "_metadata", return_value=metadata) as inspect:
      self.assertEqual([metadata], image_lifecycle.image_inventory("podman"))
    run.assert_called_once_with("podman", "image", "ls", "--all", "--no-trunc", "--quiet",
        "--filter", "label=io.decent.image.repository=https://github.com/jetpen/decent-keycloak",
        "--filter", "label=io.decent.image.component=decent-keycloak")
    inspect.assert_called_once_with("podman", image_id)

  def test_active_container_inventory_rejects_invalid_image_identity_fail_closed(self):
    container_id = "c" * 64
    for payload in ("{}", "[{}]", json.dumps([{"Image": ""}])):
      with self.subTest(payload=payload), mock.patch.object(image_lifecycle, "_run",
          side_effect=[
              subprocess.CompletedProcess([], 0, container_id + "\n", ""),
              subprocess.CompletedProcess([], 0, payload, "")]):
        with self.assertRaisesRegex(RuntimeError, "active_container_inventory_invalid"):
          image_lifecycle.active_image_ids("podman")

  def test_policy_keeps_recent_active_and_pinned_images_and_expires_old_images(self):
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    recent = {"Id": "sha256:" + "a" * 64, "Created": (now - timedelta(days=2)).isoformat(),
        "RepoTags": ["localhost/decent-keycloak/wallet-provider:recent"],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    expired = {"Id": "sha256:" + "b" * 64, "Created": (now - timedelta(days=4)).isoformat(),
        "RepoTags": ["localhost/decent-keycloak/wallet-provider:expired"],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    pinned = {"Id": "sha256:" + "c" * 64, "Created": (now - timedelta(days=8)).isoformat(),
        "RepoTags": ["localhost/decent-keycloak/wallet-provider:pin-integration"],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    active = {"Id": "sha256:" + "d" * 64, "Created": (now - timedelta(days=8)).isoformat(),
        "RepoTags": ["localhost/decent-keycloak/wallet-provider:active"],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    extended = {"Id": "sha256:" + "e" * 64, "Created": (now - timedelta(days=8)).isoformat(),
        "RepoTags": ["localhost/decent-keycloak/wallet-provider:retain-until-20261110T000000Z"],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}

    by_id = {item["Id"]: item for item in (recent, expired, pinned, active, extended)}
    with mock.patch.object(image_lifecycle, "image_inventory",
        return_value=[recent, expired, pinned, active, extended]), \
        mock.patch.object(image_lifecycle, "_metadata", side_effect=lambda _engine, image: by_id.get(image)), \
        mock.patch.object(image_lifecycle, "active_image_ids", return_value={active["Id"]}), \
        mock.patch.object(image_lifecycle, "remove_image", return_value=True) as remove:
      result = image_lifecycle.cleanup_images("podman", max_age_days=3, now=now)

    self.assertEqual([expired["Id"]], result["removed_ids"])
    self.assertEqual(1, result["kept_recent"])
    self.assertEqual(1, result["kept_pinned"])
    self.assertEqual(1, result["kept_active"])
    self.assertEqual(1, result["kept_extended"])
    remove.assert_called_once_with("podman", expired["Id"], now=now,
        cutoff=now - timedelta(days=3))

  def test_cleanup_never_selects_images_without_exact_repository_label(self):
    upstream = {"Id": "sha256:" + "a" * 64, "Created": "2000-01-01T00:00:00Z",
        "RepoTags": ["registry.example/base:latest"],
        "Config": {"Labels": {"io.decent.image.component": "decent-keycloak"}}}
    with mock.patch.object(image_lifecycle, "image_inventory", return_value=[upstream]), \
        mock.patch.object(image_lifecycle, "active_image_ids", return_value=set()), \
        mock.patch.object(image_lifecycle, "remove_image") as remove:
      result = image_lifecycle.cleanup_images("podman", max_age_days=3,
          now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    self.assertEqual([], result["removed_ids"])
    remove.assert_not_called()

  def test_expired_container_images_are_removed_only_after_exact_owner_readback(self):
    image_id = "sha256:" + "a" * 64
    old = {"Id": image_id, "Created": "2026-10-20T00:00:00Z", "RepoTags": [],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    with mock.patch.object(image_lifecycle, "_metadata", return_value=old) as inspect, \
        mock.patch.object(image_lifecycle, "active_image_ids", return_value=set()), \
        mock.patch.object(image_lifecycle, "_image_ids", return_value=set()) as inventory, \
        mock.patch.object(image_lifecycle, "_run", return_value=mock.Mock(returncode=0)) as run:
      self.assertTrue(image_lifecycle.remove_image("podman", image_id,
          now=datetime(2026, 11, 1, tzinfo=timezone.utc),
          cutoff=datetime(2026, 10, 29, tzinfo=timezone.utc)))
    inspect.assert_called_once_with("podman", image_id)
    inventory.assert_called_once_with("podman")
    run.assert_called_once_with("podman", "image", "rm", image_id, check=False)

  def test_cleanup_fails_closed_when_inventory_cannot_be_read(self):
    failed = subprocess.CompletedProcess([], 1, "", "unavailable")
    with mock.patch.object(image_lifecycle.subprocess, "run", return_value=failed):
      with self.assertRaisesRegex(RuntimeError, "container_engine_command_failed"):
        image_lifecycle.image_inventory("podman")

  def test_removal_rechecks_owner_and_active_container_before_deleting(self):
    image_id = "sha256:" + "a" * 64
    old = {"Id": image_id, "Created": "2026-10-20T00:00:00Z", "RepoTags": [],
        "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    with mock.patch.object(image_lifecycle, "_metadata", return_value={**old,
        "Config": {"Labels": {**TEST_REPOSITORY_LABELS, "io.decent.image.role": "other"}}}), \
        self.assertRaisesRegex(RuntimeError, "ownership_readback"):
      image_lifecycle.remove_image("podman", image_id, now=now)

    with mock.patch.object(image_lifecycle, "_metadata", return_value=old), \
        mock.patch.object(image_lifecycle, "active_image_ids", return_value={image_id}), \
        mock.patch.object(image_lifecycle, "_run") as run:
      with self.assertRaisesRegex(RuntimeError, "became_active"):
        image_lifecycle.remove_image("podman", image_id, now=now)
    run.assert_not_called()

  def test_cli_defaults_to_three_days_and_allows_explicit_environment_configuration(self):
    with mock.patch.object(image_lifecycle, "cleanup_images", return_value={
        "removed_ids": [], "kept_recent": 0, "kept_pinned": 0,
        "kept_extended": 0, "kept_active": 0}) as cleanup, \
        mock.patch.dict(image_lifecycle.os.environ, {}, clear=True), \
        contextlib.redirect_stdout(io.StringIO()):
      self.assertEqual(0, image_lifecycle.main(["--engine", "podman", "cleanup"]))
    self.assertEqual(3, cleanup.call_args.kwargs["max_age_days"])
    with mock.patch.object(image_lifecycle, "cleanup_images", return_value={
        "removed_ids": [], "kept_recent": 0, "kept_pinned": 0,
        "kept_extended": 0, "kept_active": 0}) as cleanup, \
        mock.patch.dict(image_lifecycle.os.environ, {"DECENT_IMAGE_RETENTION_DAYS": "7"}), \
        contextlib.redirect_stdout(io.StringIO()):
      self.assertEqual(0, image_lifecycle.main(["--engine", "podman", "cleanup"]))
    self.assertEqual(7, cleanup.call_args.kwargs["max_age_days"])

  def test_component_role_provenance_and_publication_boundary_are_documented_and_enforced(self):
    dockerfile = (Path(__file__).parents[1] / "container/Dockerfile").read_text()
    stages = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    self.assertEqual(len(stages), dockerfile.count("io.decent.image.repository="))
    self.assertEqual(len(stages), dockerfile.count("ARG IMAGE_ROLE="))
    self.assertEqual(len(stages), dockerfile.count('case "$SOURCE_REVISION"'))
    self.assertEqual(len(stages), dockerfile.count('case "$IMAGE_SOURCE_SHA256"'))
    self.assertEqual(len(stages), dockerfile.count('case "$IMAGE_ARTIFACTS_SHA256"'))
    self.assertNotIn("ARG SOURCE_REVISION=unknown", dockerfile)
    self.assertNotIn("ARG IMAGE_SOURCE_SHA256=unknown", dockerfile)
    self.assertNotIn("ARG IMAGE_ARTIFACTS_SHA256=unknown", dockerfile)
    for label in ("io.decent.image.component=", "io.decent.image.source-revision=",
        "io.decent.image.source-sha256=", "io.decent.image.artifacts-sha256="):
      self.assertEqual(len(stages), dockerfile.count(label))
    for target in lifecycle.IMAGE_BUILD_ARTIFACTS_BY_TARGET:
      self.assertIn(f" AS {target}", dockerfile)
    self.assertEqual("localhost/decent-keycloak/wallet-provider", image_lifecycle.IMAGE_PREFIX)

    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text()
    workflow = (root / ".github/workflows/acceptance.yml").read_text()
    lifecycle_evidence = (root / "docs/acceptance/issue-26-image-lifecycle.md").read_text()
    self.assertIn("docs/acceptance/issue-26-image-lifecycle.md", readme)
    self.assertIn("30 days", lifecycle_evidence)
    self.assertIn("90 days", lifecycle_evidence)
    self.assertIn("does not have `read:packages`", lifecycle_evidence)
    self.assertIn("Never delete a manifest while a confirmed downstream consumer still uses its digest", lifecycle_evidence)
    self.assertIn("Local engine verification (2026-11-01)", lifecycle_evidence)
    self.assertIn("same Podman store", lifecycle_evidence)
    self.assertIn("age was advanced through the cleanup function's injected clock", lifecycle_evidence)
    self.assertIn("registry/repository@sha256:", lifecycle_evidence)
    for path, target in (("issue-6-postconsume-runtime.md", "issue6-postconsume-test-runtime"),
        ("issue-7-store-recovery.md", "issue7-store-recovery-test-runtime"),
        ("issue-7-user-readback-recovery-profile.md", "issue7-user-readback-test-runtime")):
      instructions = (root / "docs/acceptance" / path).read_text()
      self.assertIn('--build-arg SOURCE_REVISION="$(git rev-parse HEAD)"', instructions)
      self.assertIn(f"image-fingerprints --target {target} --field image_source_sha256", instructions)
      self.assertIn(f"image-fingerprints --target {target} --field image_artifacts_sha256", instructions)
      self.assertIn('--build-arg IMAGE_SOURCE_SHA256="$IMAGE_SOURCE_SHA256"', instructions)
      self.assertIn('--build-arg IMAGE_ARTIFACTS_SHA256="$IMAGE_ARTIFACTS_SHA256"', instructions)
    callback_instructions = (root / "docs/acceptance/issue-6-postconsume-runtime.md").read_text()
    self.assertIn("image-fingerprints --target issue6-callback-gate-test-runtime --field image_source_sha256",
        callback_instructions)
    self.assertIn("image-fingerprints --target issue6-callback-gate-test-runtime --field image_artifacts_sha256",
        callback_instructions)
    self.assertIn("--target issue6-callback-gate-test-runtime", callback_instructions)
    self.assertIn("contents: read", workflow)
    self.assertNotIn("packages: write", workflow)
    self.assertNotIn("skopeo copy", workflow)

  def test_retention_tag_write_requires_readback_of_same_immutable_id_and_tag(self):
    image_id = "sha256:" + "a" * 64
    tag = image_lifecycle.IMAGE_PREFIX + ":pin-consumer"
    image = {"Id": image_id, "RepoTags": [tag], "Config": {"Labels": TEST_REPOSITORY_LABELS}}
    with mock.patch.object(image_lifecycle, "_run", return_value=mock.Mock(returncode=0)) as run, \
        mock.patch.object(image_lifecycle, "_metadata", return_value=image) as inspect:
      image_lifecycle.tag_image("podman", image_id, tag)
    run.assert_called_once_with("podman", "image", "tag", image_id, tag)
    inspect.assert_called_once_with("podman", image_id)

    missing_tag = {**image, "RepoTags": []}
    with mock.patch.object(image_lifecycle, "_run", return_value=mock.Mock(returncode=0)), \
        mock.patch.object(image_lifecycle, "_metadata", return_value=missing_tag):
      with self.assertRaisesRegex(RuntimeError, "retention_tag_readback_failed"):
        image_lifecycle.tag_image("podman", image_id, tag)

  def test_pin_and_extend_tags_are_validated_and_keep_exact_image_id(self):
    image_id = "sha256:" + "a" * 64
    with mock.patch.object(image_lifecycle, "resolve_image_id", return_value=image_id), \
        mock.patch.object(image_lifecycle, "tag_image") as tag:
      image_lifecycle.pin_image("podman", "some-local-tag", "integration")
      image_lifecycle.extend_image("podman", "some-local-tag", 10,
          now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    self.assertEqual(image_id, tag.call_args_list[0].args[1])
    self.assertIn(":pin-integration", tag.call_args_list[0].args[2])
    self.assertIn(":retain-until-20261111T000000Z", tag.call_args_list[1].args[2])
    for invalid in ("../bad", "bad name", ""):
      with self.assertRaises(ValueError):
        image_lifecycle.pin_image("podman", "some-local-tag", invalid)


if __name__ == "__main__":
  unittest.main()
