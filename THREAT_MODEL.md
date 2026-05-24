# Threat Model

## Overview

OpenAuthority is an experimental constrained-root trust infrastructure designed to explore:
- continuously verified trust anchors,
- transparency logging,
- constrained certificate authority delegation,
- and independently reproducible trust store exports.

This document outlines the project's current threat model, security assumptions, and known limitations.

OpenAuthority is research-oriented software and should not be considered production-grade Internet trust infrastructure.

---

# Security Goals

The primary goals of OpenAuthority are:

- Reduce implicit trust in certificate authorities
- Constrain authority scope to explicitly verified namespaces
- Make trust decisions observable and auditable
- Detect unauthorized or unverifiable trust relationships
- Provide independently reproducible trust store exports
- Preserve append-only audit history
- Support external timestamp anchoring and verification

---

# Threats Considered

## Malicious or Compromised Certificate Authorities

Traditional PKI systems often grant broad signing authority to trusted roots.

OpenAuthority attempts to reduce this risk by:
- constraining certificate authorities to verified namespaces,
- requiring DNS ownership validation,
- and continuously re-validating ownership claims.

A compromised CA should not be able to:
- transparently expand authority scope,
- silently modify trust state,
- or remove audit history without detection.

---

## Unauthorized Namespace Claims

An attacker may attempt to:
- claim authority over domains they do not control,
- spoof DNS responses,
- or exploit parser ambiguities.

Mitigations include:
- multi-resolver verification,
- DNS response validation,
- hardened packet parsing,
- and periodic re-verification.

---

## Audit Log Tampering

An attacker may attempt to:
- rewrite trust history,
- delete historical events,
- or modify verification outcomes.

OpenAuthority mitigates this through:
- append-only audit logging,
- cryptographic hash chaining,
- Merkle tree inclusion proofs,
- and optional external timestamp anchoring.

Tampering with historical entries should be detectable by independent verification.

---

## Resource Exhaustion Attacks

Attackers may attempt to:
- exhaust Worker memory,
- trigger excessive recursion,
- generate oversized proofs,
- or force expensive parsing operations.

Mitigations include:
- explicit resource limits,
- bounded recursion depth,
- proof size limits,
- parser validation limits,
- and incremental Merkle tree construction.

The current implementation is designed around Cloudflare Worker resource constraints.

---

## Malformed Certificate and ASN.1 Structures

ASN.1 and X.509 parsing are historically high-risk areas.

OpenAuthority includes:
- defensive ASN.1 parsing,
- explicit bounds validation,
- constrained extension handling,
- and rejection of malformed structures where possible.

However:
- ASN.1 parsing remains security-sensitive,
- and the implementation has not undergone formal audit.

---

## DNS Resolver Manipulation

DNS-based ownership verification introduces dependency on DNS infrastructure.

Threats include:
- resolver compromise,
- response forgery,
- cache poisoning,
- and selective response manipulation.

Mitigations currently include:
- multi-resolver verification,
- response validation,
- and consistency checks.

OpenAuthority does not currently defend against:
- nation-state DNS interception,
- fully compromised recursive resolver ecosystems,
- or malicious authoritative DNS operators.

---

## Transparency Log Forking

An attacker controlling infrastructure may attempt to:
- present inconsistent views of the audit log,
- fork transparency state,
- or suppress entries.

External timestamp anchoring and reproducible exports are intended to increase the difficulty of undetected log divergence.

This area remains an active research concern.

---

# Explicit Non-Goals

OpenAuthority does not currently attempt to solve:

- Browser trust integration
- Certificate revocation at Internet scale
- Nation-state adversaries
- Hardware-backed root key protection
- Formal cryptographic verification
- Byzantine consensus
- Distributed transparency federation
- Secure client update distribution
- Resistance against fully compromised hosting providers

---

# Security Assumptions

The current design assumes:

- DNS ownership meaningfully represents namespace control
- At least some DNS resolvers behave honestly
- Cloudflare Workers and D1 behave correctly
- External timestamp services are independently operated
- Audit log observers independently verify exported state
- Export signing keys remain uncompromised

Compromise of signing infrastructure may allow:
- malicious trust exports,
- forged manifests,
- or misleading verification results.

---

# Operational Risks

Operators should be aware of several important operational risks:

- DNS ownership may change over time
- Resolver behavior may differ regionally
- Cloudflare Worker limits may impact large-scale operation
- D1 is not designed for globally distributed append-only consensus systems
- Large transparency logs may require architectural redesign
- Export reproducibility depends on deterministic serialization behavior

---

# Current Limitations

The current implementation:
- has not undergone independent security audit,
- has not received formal cryptographic review,
- and has not been evaluated under adversarial Internet-scale conditions.

The project should currently be considered:
- experimental,
- research-oriented,
- and unsuitable for production-critical trust decisions without independent evaluation.

---

# Future Areas of Research

Potential future work includes:

- Federated transparency verification
- Gossip-based consistency validation
- Signed checkpoint ecosystems
- Threshold trust models
- Formal verification of log behavior
- Improved DNS trust minimization
- Incremental trust synchronization
- Distributed witness infrastructure
- Reproducible build verification
- Hardware-backed signing infrastructure

---

# Responsible Disclosure

Security issues should be reported privately to the project maintainers before public disclosure whenever possible.

See `SECURITY.md` for reporting instructions.