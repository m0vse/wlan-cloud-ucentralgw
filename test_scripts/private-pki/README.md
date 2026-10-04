# Isolated private PKI gateway checks

Private policy is disabled unless `openwifi.privatepki.policy` names a trusted
local file. Enabling it requires strict TLS client verification. The short-lived
policy contains approved serial/leaf pins and revocations, with a monotonic
version. Admission and serial matching happen before session replacement,
inventory creation, queue clearing or configuration dispatch. Inbound/outbound
traffic is rechecked, and a two-second worker closes revoked or expired sessions.

`policy_test.cpp` and `make_fixtures.py` exercise native policy validation:
exact leaf and CN, client EKU, validity, disabled inventory, revocation, expiry,
version rollback, same-version replacement, unsafe file mode and symlinks.

`runtime_fixtures.py DESTINATION` creates three-day disposable RSA certificates
and a standalone gateway configuration from the repository defaults. Authority
signing keys are never exported. Device/server test keys are owner-only. Keep
the entire output outside the repository. The configuration is test-only:
API transport encryption is disabled inside a Docker `--network none` container;
the state reader still uses the gateway's authenticated internal API. There
must be no host ports, live database, live CA files or physical AP connection.

Build the actual gateway, extract these fixtures into `/tmp/runtime`, and run
`session_test.py` inside that same network-isolated container. The test uses real
TLS client connections and native WebSocket connect messages. It checks exact
leaf/nonce/policy/session acceptance via the gateway API; unapproved same-serial
leaf and mismatched serial denial without replacing an accepted session;
revocation closing the current transport; refused revoked reconnection;
retained legacy-CA admission while the new-CA leaf is revoked, including denial
of a revoked connection that would otherwise replace that legacy session;
restored admission with a fresh session; and policy-expiry disconnection.

Validated on 2026-10-04 with a complete rebuild of all objects affected by the
connection-state header. Incremental tar overlays can retain older timestamps;
rebuild affected dependencies after such overlays. Native policy and actual
session checks passed. These checks do not demonstrate production activation,
portal deployment, AP reboot retention, root retirement or hardware migration.

The optional connect challenge is observed from the authenticated TLS session;
`privateLeafSha256`, `privateActivationNonce`, `privateAcceptedAt` and
`privatePolicyVersion` are populated only after the normal gateway connect
processing succeeds. A separate protected backend consumes its fresh challenge
once. A TLS handshake, client claim or certificate issuance alone is insufficient.
