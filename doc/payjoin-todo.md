# Payjoin follow-up work

Future work for [RPC](payjoin-rpc.md).

## Recovery

Payment records, journals, ownership records and coin locks can outlive RPC access.
Reservations protect potentially exposed inputs; see [Lifetime](payjoin-rpc.md#lifetime).

Recovery must restore RPC views and `request_id` idempotency. Version records, saved request
parameters and journals for FFI upgrades; reconcile them, ownership, locks and transactions
against wallet and chain, including corrupt, unknown and expired states. Requires durable
storage and shared input ownership.

Completion: reload, restart, crash, uncertain-write and backup restoration tests verify
deduplication, mismatch rejection, locks, ownership and safe controls. Never resume negotiation
or repeat the initial POST automatically; retain inputs while delivery, ownership or storage is uncertain.

## Admission

Move [typed v2 checks](../src/wallet/payjoin/sender.cpp#L182) and shared relay validation
before registration, signing or reservation: v1 or invalid relays can now pass admission.

Completion: malformed or configuration-invalid requests leave no records, claimed
`request_id`, signatures, locks or network requests. Separate configuration faults from network failures.

## Resources and history

Bound sessions, queues, history and notifications across wallets; define retention and pagination.
Requires recovery and idempotency retention; pagination alone does not bound internal scans.

Completion: bounded memory, command latency and shutdown under load; pruning preserves
idempotency and recovery records, and no wallet can starve another.

## Reproducible depends sources

Define archive contents excluding Git, build artifacts and junk, without touching checkout
timestamps. Requires explicit source selection and prepared Cargo dependencies.

Completion: identical sources yield identical archives regardless of directory or junk.
Clean builds need no pre-warmed Cargo cache; separate fetching from offline builds.

## Transaction compatibility

Define P2WPKH, P2TR and mixed sender input, receiver contribution and change compatibility
against wallet policy and pinned FFI capabilities.

Completion: a matrix checks signatures, fees, contribution and mempool acceptance;
unsupported combinations are explicitly rejected.

## CI and fuzzing

Add sanitizer jobs, Core FFI fuzzing and ordinary wallet and RPC regressions. Requires
reproducible builds with C++ and Rust instrumentation; completion: passing jobs and fuzz runs with coverage.

## Async v2 receiver

Build a production async wallet service, adapter and RPC around
[receiver FFI](../payjoin/payjoin-ffi/src/receive/mod.rs#L538), currently used in Core tests.
