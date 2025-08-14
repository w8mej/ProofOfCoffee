
# Security Policy

This repository is a **proof of concept**. It demonstrates ideas around
zero-trust, short-lived credentials, and YubiKey-backed MPC. Do **not** use as-is
for production.

- No real TEE attestation is implemented.
- The "YubiKey" modules are mocks for local development unless replaced with
  actual PIV/OpenPGP implementations.
- Threshold signing is simulated with Shamir secret sharing and an in-memory
  reconstruction performed by a "coordinator". Replace with real FROST/MPC + HSMs.
- Tokens are short-lived and scoped but policy enforcement is minimal.

If you discover a vulnerability, please open an issue **without** sensitive details,
then email the maintainer privately.
