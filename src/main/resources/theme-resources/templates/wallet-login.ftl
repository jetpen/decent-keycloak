<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section = "header">
    Wallet challenge
  <#elseif section = "form">
    <div class="alert alert-info" role="status">
      <p>Scan this QR code with your wallet to continue.</p>
      <p id="wallet-origin">${walletOriginLabel?html}</p>
      <p>Challenge expires at ${walletExpiresAt?html}.</p>
    </div>
    <img id="wallet-qr" alt="Wallet challenge QR code" src="${walletQrDataUri?html}" />
    <p id="wallet-locator">${walletChallengeLocator?html}</p>
    <p id="wallet-state" role="status">Waiting for wallet approval…</p>
    <p class="instruction">Open this login page only through your relying party. The wallet must confirm this origin before approving. Do not share the QR URL.</p>
    <script>
      (function () {
        "use strict";
        const state = document.getElementById("wallet-state");
        const statusUrl = "${walletStatusUri?js_string}";
        const csrfToken = "${walletCsrfToken?js_string}";
        let attempts = 0;
        let polling = false;
        const poll = async () => {
          if (polling) return;
          polling = true;
          if (++attempts > 150) {
            state.textContent = "Challenge expired. Restart login.";
            polling = false;
            return;
          }
          try {
            const response = await fetch(statusUrl, {
              credentials: "same-origin",
              cache: "no-store",
              headers: {"Accept": "application/json", "X-Decent-CSRF": csrfToken}
            });
            if (response.ok) {
              const status = await response.json();
              if (status.status === "accepted" && status.callback) {
                const candidate = new URL(status.callback, window.location.origin);
                if (candidate.origin !== window.location.origin) throw new Error("callback origin mismatch");
                window.location.assign(candidate.href);
                return;
              }
              if (status.status === "expired" || status.status === "rejected") {
                state.textContent = "Challenge expired or rejected. Restart login.";
                return;
              }
            } else if (response.status === 404) {
              state.textContent = "Challenge expired. Restart login.";
              return;
            }
          } catch (_) {
            // Keep polling this same browser-bound transaction after transient errors.
          }
          polling = false;
          window.setTimeout(poll, 2000);
        };
        window.setTimeout(poll, 1500);
      }());
    </script>
  </#if>
</@layout.registrationLayout>
