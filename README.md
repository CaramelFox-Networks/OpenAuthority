# OpenAuthority

Experimental constrained-root trust infrastructure with continuous DNS verification, transparency logging, and reproducible trust store exports.

OpenAuthority explores an alternative trust distribution model where certificate authorities are:
- constrained to explicitly verified namespaces,
- continuously re-validated,
- transparently audited,
- and cryptographically logged.

This project is intentionally experimental and research-oriented.

---

## Features

- Constrained certificate authority trust model
- Continuous DNS TXT ownership verification
- Multi-resolver verification support
- Append-only transparency log with Merkle proofs
- External timestamp anchoring support (RFC3161/Rekor)
- Reproducible trust store exports
- Signed export manifests
- Cryptographic audit log chaining
- Cloudflare Workers + D1 deployment model

---

## Design Goals

OpenAuthority is designed around several core principles:

- Minimize implicit trust
- Make trust decisions observable and auditable
- Reduce authority scope using constraints
- Continuously verify ownership instead of relying on static issuance
- Support reproducible and independently verifiable exports

---

## Non-Goals

OpenAuthority is not:
- a replacement for the WebPKI,
- a browser-integrated CA ecosystem,
- or production-ready Internet trust infrastructure.

This project exists to explore constrained trust distribution and transparency mechanisms.

---

## Architecture Overview

Certificate authorities are verified using DNS TXT proofs and periodically re-validated. Successful verification events are recorded in an append-only audit log protected by:
- cryptographic hash chaining,
- Merkle tree inclusion proofs,
- and optional external timestamp anchoring.

Trust store exports are deterministic and independently verifiable.

---

## Security Notes

This project includes:
- explicit threat model documentation,
- defensive ASN.1 parsing,
- hardened DNS packet parsing,
- resource exhaustion protections,
- and audit log integrity verification.

That said:

> This software is experimental and has not undergone formal security review or external audit.

Do not rely on it for production-critical trust decisions without independent evaluation.

---

## Deployment

OpenAuthority currently targets:

- Cloudflare Workers
- Cloudflare D1

### Basic Setup

Install dependencies:

```bash
npm install
```

Create a local Wrangler configuration:

```bash
cp wrangler-example.toml wrangler.toml
```

Apply the database schema:

```bash
wrangler d1 execute <DATABASE_NAME> --file=schema.sql
```

Run locally:

```bash
wrangler dev
```

Deploy:

```bash
wrangler deploy
```

---

## License

Licensed under the GNU Affero General Public License v3.0 or later.

See `LICENSE` for details.

---

## Trademark Notice

“OpenAuthority” and “CaramelFox” are trademarks or service marks of CaramelFox Networks LLC.

The AGPL license does not grant rights to use project branding, trademarks, or service marks.