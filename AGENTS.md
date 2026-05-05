# AGENTS.md

## Project: Secure DNS Proxy (systemd-resolved Replacement)

---

## 1. Purpose

This project aims to replace `systemd-resolved` with a **modern, secure, high-performance DNS resolver**.

The system must act as a **local stub resolver** that:

* Listens on a loopback address (default: `127.0.0.35:53`)
* Transparently resolves DNS for the host
* Enforces secure DNS transport wherever possible
* Provides predictable, debuggable behavior

This is not a library. This is a **system component**.

---

## 2. Core Goals

### 2.1 Functional Goals

* Replace `systemd-resolved` for:

  * Local DNS resolution
  * `/etc/resolv.conf` integration
  * Stub resolver behavior

* Support multiple upstream protocols:

  * Plain DNS (fallback only)
  * DNS-over-TLS (DoT)
  * DNS-over-HTTPS (DoH)
  * DNS-over-QUIC (DoQ)

* Provide:

  * Deterministic resolution behavior
  * Configurable upstream selection
  * Fast response times under load

---

### 2.2 Security Goals

* Default to encrypted DNS (DoH, DoT, DoQ)
* Prevent silent downgrade to plaintext DNS unless explicitly configured
* Enforce TLS validation by default
* Isolate and fail unhealthy upstreams
* Avoid leaking queries across upstreams unintentionally

---

### 2.3 Performance Goals

* Sub-millisecond cache hits
* Minimal allocation in hot paths
* Connection reuse (TLS and QUIC pooling)
* Request coalescing (no duplicate upstream queries)
* Efficient concurrency under high QPS

---

### 2.4 Reliability Goals

* Continue operating with partial upstream failure
* Gracefully degrade (not crash) under stress
* Avoid request amplification or retry storms
* Provide bounded latency via timeouts and rate limiting

---

## 3. Non-Goals

Do not implement:

* Full recursive resolver (this is a forwarder, not Unbound)
* DNSSEC validation (future consideration, not core scope)
* GUI or desktop integration layers
* Feature parity with every `systemd-resolved` quirk

Avoid:

* Over-engineering configuration formats
* Hidden or implicit behavior
* Silent fallback logic that obscures failures

---

## 4. Architecture Overview

### Request Flow

Client → Ingress Server → Resolver → Cache → Upstream Manager → Upstream

### Core Components

* **Ingress**

  * UDP + TCP DNS listener
  * Handles client requests

* **Resolver**

  * Coordinates cache and upstream queries
  * Applies rate limiting and timeouts

* **Cache**

  * TTL-based response storage
  * Negative caching (NXDOMAIN)
  * Request coalescing

* **Upstream Manager**

  * Selects upstream based on policy:

    * round_robin
    * sequential
    * race (fastest wins)

* **Upstreams**

  * DoH, DoT, DoQ, plain DNS

* **Connection Pools**

  * TLS and QUIC reuse
  * Prewarming support

* **Metrics + Logging**

  * Structured logs
  * Atomic counters

---

## 5. Configuration Principles

* JSON-based configuration
* Safe defaults must require zero tuning
* Explicit over implicit
* Runtime reload support preferred over restart

Key configurable areas:

* Upstreams
* Cache behavior
* Timeouts
* Rate limits
* Logging level

---

## 6. System Integration Requirements

* Must run as a system service (systemd unit expected)

* Must bind to a local stub address (not public by default)

* Must integrate with:

  * `/etc/resolv.conf`
  * Network managers (without tight coupling)

* Must not require:

  * Containers
  * External orchestration

---

## 7. Observability

* Logs must be:

  * Structured
  * Human-readable
  * Useful for debugging resolution issues

* Metrics must include:

  * Cache hit/miss rates
  * Upstream success/failure
  * Request counts
  * Traffic volume

---

## 8. Design Constraints

* No global mutable state without synchronization
* No blocking operations in hot paths without bounds
* No unbounded memory growth
* No hidden retries

Every decision should prioritize:

1. Correctness
2. Predictability
3. Performance

---

## 9. Expectations for Agents (Human and AI)

### Required Behavior

* Read this file before making changes
* Respect scope and non-goals
* Prefer simple, explicit solutions
* Justify complexity when introduced

### When modifying code:

* Do not introduce:

  * Silent fallbacks
  * Hidden side effects
  * Implicit configuration behavior

* Always consider:

  * Performance impact
  * Failure modes
  * Observability

### When adding features:

* Must align with core goals
* Must not degrade security defaults
* Must not increase ambiguity in behavior

---

## 10. Future Extensions (Not Core Scope)

These are acceptable later, but not required now:

* DNSSEC validation
* Persistent cache
* eBPF-based traffic insights
* Advanced policy routing (per-domain upstream selection)
* Admin API

---

## 11. Definition of Done

A feature is complete when:

* It behaves deterministically
* It is observable via logs/metrics
* It does not degrade performance under load
* It respects security defaults
* It integrates cleanly with the existing architecture

---

## 12. Guiding Principle

This project is not trying to be everything.

It is trying to be:

> A fast, secure, predictable DNS resolver that you can trust on every system

If a change does not support that goal, it does not belong.

