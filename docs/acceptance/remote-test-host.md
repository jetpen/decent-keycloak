# Remote test-host lifecycle

`remote-test-host` is an explicitly authorized, tailnet-only integration profile. It runs the normal local build/test/image-smoke lifecycle, transfers the exact built immutable image over Tailscale SSH, starts a temporary Keycloak instance, and validates the HTTPS master-realm OIDC discovery document and exact issuer. It does not qualify browser, Android, wallet, or production behavior.

## Configuration and prerequisites

The default target is `ben-x260.tailca8b51.ts.net` as user `ben`. Override it with `REMOTE_TEST_HOST` and `REMOTE_TEST_USER` in the local environment. The configured host value must exactly match the target's Tailscale self DNS name. The local host requires rootless Podman and Tailscale SSH; the target requires Tailscale SSH access, rootless Podman, Python 3.10+, and an unused loopback port 8080.

Before running, verify `tailscale status --json` on the target reports the configured self DNS name and confirm the tailnet SSH access policy permits the intended user. If Tailscale SSH is not already enabled on the target, an administrator can enable it with `sudo tailscale set --ssh=true`. To let the configured unprivileged user manage Tailscale port-forwarding settings, an administrator can grant the local operator role once with `sudo tailscale set --operator=ben` (replace `ben` when `REMOTE_TEST_USER` differs). Tailscale Serve also requires HTTPS certificates to be enabled for the tailnet in the admin console's DNS settings. Enabling certificates publishes the device and tailnet DNS names in public certificate-transparency logs; obtain the owner's approval before enabling this if it is not already configured. See [Tailscale SSH](https://tailscale.com/docs/reference/ssh-over-tailscale), [Linux operator permissions](https://tailscale.com/docs/reference/troubleshooting/linux/linux-operator-permission), and [Tailscale HTTPS certificates](https://tailscale.com/docs/how-to/set-up-https-certificates).

Do not manually configure Serve first: read-only preflight requires an unused Serve configuration and free port 8080. No target-side deployment script needs to be installed. The helper is sent over Tailscale SSH and configures a single tailnet-only Serve route for the run; use `tailscale serve status` after completion to confirm it has been removed. Do not enable Funnel or run `tailscale funnel`.

Use the opt-in command only after explicit approval for that exact run:

```bash
python3.11 scripts/lifecycle.py run remote-test-host --allow-live
```

The profile does not enable Tailscale Funnel, publish a registry image, or expose Keycloak directly on a network interface. Keycloak binds to `127.0.0.1:8080`; Tailscale Serve provides the private tailnet HTTPS route. The generated bootstrap admin password is created inside the target-side helper and passed to Podman through a private process environment, never as a command argument, local lifecycle variable, log, or receipt.

## Image and cleanup safety

The image archive is streamed from local Podman to target Podman over Tailscale SSH and inspected by full immutable image ID. The target uses the lifecycle's run-scoped transfer alias and `decent-keycloak:lifecycle-<run-id>`; it never retags or removes the existing `decent-keycloak:latest` alias. The container name, ownership labels, and immutable image ID are bound to the same random lifecycle run ID. Teardown verifies the exact single Serve route before disabling it, removes only the full container ID with matching run/image labels, removes only the two run-scoped image aliases with a matching immutable ID, and reads back that the container, route, and aliases are absent. A mismatch or inconclusive readback fails closed rather than removing an unrelated resource.

The sanitized receipt is written under `target/lifecycle/evidence/`. Remote state changes are not retried automatically. Review a failed receipt and the target manually before any separately authorized attempt.
