# Issue #6 expiry sequencing run log

## Scope

Offline-only implementation on the clean implementer worktree. No containers, image builds, Podman commands, live profiles, or qualification were performed.

## TDD RED

Command:

```text
python3.11 -m unittest scripts.test_wallet_login_transport_e2e.AuthStatusBindingProbeTest.test_single_node_profile_runs_auth_then_expiry_with_bounded_checkpoint -v
```

The first invocation exposed that the dispatcher had no checkpoint seam (`TypeError: ... unexpected keyword argument 'checkpoint'`), a feature gap but not the intended behavioral RED. The same regression was then exercised against the pre-slice `issue6-single-node` dispatcher: it failed the asserted order because the observed calls were only `['auth_flow']`, with no expiry phase. This was an assertion failure, not setup/compiler failure. The regression also checks the sanitized auth checkpoint, final evidence, and that an expiry failure leaves the phase-one checkpoint intact.

## TDD GREEN

Same focused command passed: 1 test, 0 failures/errors. The profile now calls auth, writes the sanitized checkpoint, runs expiry, and returns bounded evidence for both phases. Full offline suite/build results are recorded in README after final verification.

## Maven invocation adjustment

The first offline packaging attempt used `MAVEN_SKIP_RC=true` and failed before compilation because the legacy `MaxPermSize=128m` option was still loaded by Maven's RC configuration. Retrying with the established `MAVEN_SKIP_RC=1` invocation passed the full package and tests. No global or user configuration was changed.

## Cleanup-interrupt TDD RED

Command:

```text
python3.11 -m unittest scripts.test_wallet_login_transport_e2e.MainCleanupFailureTest.test_cleanup_interrupt_is_preserved_after_all_cleanup_attempts -v
```

The test failed on the required behavior: cleanup converted the injected `KeyboardInterrupt` into `SystemExit(1)` (`SystemExit(1) is not KeyboardInterrupt(...)`). The test also verifies that independent cleanup continues, cleanup diagnostics omit interrupt messages, and a pre-existing primary exception or interruption is preserved over a teardown `SystemExit`.

## Cleanup-interrupt TDD GREEN

The same focused cleanup class passed: 4 tests, 0 failures/errors. The interruption regression confirms exact exception identity is restored after teardown, while all three independent cleanup operations are attempted. Existing checks still confirm normal cleanup failures after success exit nonzero, active primary failures win, clean success stays successful, and diagnostic output contains no raw exception text.
