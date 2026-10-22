# Payjoin build and tests

Reuse separate build directories for production and integration. See [wallet RPC](payjoin-rpc.md).

## Prerequisites

Use Linux or Ubuntu WSL from the source root: CMake 3.24+, [Unix tools](build-unix.md),
[depends prerequisites](../depends/README.md), Git, Python 3, `cargo` and `rustc` in `PATH`.
Examples use depends curl and OpenSSL; system libcurl needs 8.22+ and async DNS. Install Rust 1.85.1:

```sh
git submodule update --init --recursive -- payjoin
rustup toolchain install 1.85.1 --profile minimal
RUSTUP_TOOLCHAIN=1.85.1 rustc --version
RUSTUP_TOOLCHAIN=1.85.1 cargo --version
```

## Production FFI build and unit tests

These Core builds use Debug for testing. Keep `source_dir` and `depends_prefix` in one
shell. Prepare both FFI packages and CLI before Core; rerunning depends can recreate
the prefix. Downloads need network; cached runs use `CARGO_NET_OFFLINE=true`.

```sh
source_dir="$PWD"
depends_prefix="$source_dir/depends/$(./depends/config.guess)"
make -C depends -j4 PAYJOIN=1 PAYJOIN_TESTS=1 NO_QT=1 NO_IPC=1 NO_ZMQ=1 NO_USDT=1
cmake -S . -B build-payjoin \
  --toolchain "$depends_prefix/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_WALLET=ON -DENABLE_PAYJOIN=ON -DBUILD_TESTS=ON \
  -DBUILD_PAYJOIN_INTEGRATION_TESTS=OFF -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
  -DPayjoinFFI_DIR="$depends_prefix/lib/cmake/PayjoinFFI"
cmake --build build-payjoin --target test_bitcoin bitcoind bitcoin-cli -j4
./build-payjoin/bin/test_bitcoin \
  --run_test=payjoin_tests,payjoin_sender_tests,payjoin_transport_tests,payjoin_manager_tests \
  --catch_system_error=no --log_level=test_suite
```

Unit suites cover protocol and wallet/manager behavior. Sender tests use controlled transport;
HTTP tests exercise libcurl against local servers.

## Integration build and tests

Production uses release FFI without `_test-utils`; integration uses debug FFI with `cpp,_test-utils`.
CMake enforces package separation. [Recipes](../depends/packages/payjoin_ffi.mk) pin Rust, lockfile and generator.
Linking is static; the shared library generates bindings.
For system dependencies, omit `--toolchain`; use prepared `PayjoinFFI_DIR`.

```sh
cmake -S . -B build-payjoin-integration \
  --toolchain "$depends_prefix/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
  -DENABLE_WALLET=ON -DENABLE_PAYJOIN=ON -DBUILD_TESTS=ON \
  -DBUILD_PAYJOIN_INTEGRATION_TESTS=ON \
  -DPayjoinFFI_DIR="$depends_prefix/tests/payjoin-ffi/lib/cmake/PayjoinFFI"
cmake --build build-payjoin-integration --target test_payjoin_integration payjoin_test_services -j4
ctest --test-dir build-payjoin-integration \
  -L payjoin_integration --output-on-failure --no-tests=error -j1
```

Integration exchanges use in-process regtest wallets, real `SenderSession` and
TestServices; pre-exchange and HTTP-only cases cover narrower boundaries.
CTest runs cases in separate processes with 120-second timeouts; exit stops
TestServices tasks. Receiver observation proves original receipt.

## Wallet RPC functional test

```sh
python3 build-payjoin/test/functional/test_runner.py wallet_payjoin.py \
  --payjoin-cli="$depends_prefix/native/bin/payjoin-cli" \
  --payjoin-test-services="$source_dir/build-payjoin-integration/bin/payjoin_test_services"
```

Require `Passed`. Without helper paths it reports `Skipped`; supplying either requires both.
Reload tests verify loss of RPC access and a new `request_id` scope; [recovery](payjoin-todo.md#recovery) is pending.
The exchange uses P2WPKH; P2TR and mixed cases await a [matrix](payjoin-todo.md#transaction-compatibility).

The test runs Core against an upstream CLI receiver and isolated TestServices.
It checks the receiver input, publication, confirmation, reorg, idempotency,
cancellation and explicit fallback. Successful CLI exit is checked before mining;
`--timeout-factor` scales bounded waits.

## BTCPay Server regtest smoke test

Prerequisites: both nodes share the same regtest chain; the Core sender wallet is
funded and unlocked; BTCPay Async Payjoin has a hot wallet with a confirmed spendable
UTXO; the directory and OHTTP relay are reachable. Keep the sender wallet loaded.

Use the [RPC workflow](payjoin-rpc.md#minimal-workflow).

| Step | Action | Expected result |
| --- | --- | --- |
| 1 | Create an invoice, select Async Payjoin and copy the complete Bitcoin URI. | URI contains the amount and `pj=`. |
| 2 | Call `sendpayjoin` with the URI, relay, unique `request_id` and fee cap. | A `payment_id` is returned. |
| 3 | Repeat the request with identical parameters. | Same `payment_id`, `duplicate=true`. |
| 4 | Poll `getpayjoin` and inspect the selected transaction. | `published`; `selected.txid` differs from `original.txid`; a receiver-owned input is present; total fee respects the cap; original is absent from the mempool. |
| 5 | Mine enough blocks for the store's confirmation policy, poll again and check BTCPay. | `confirmed`, settlement kind `selected`, `reservations.owned=false`; invoice is Settled with the invoice amount credited and a "Settled with Payjoin" event. |

Save the invoice ID, `payment_id`, selected txid, fee and a BTCPay status screenshot.

## Verification

```sh
./build-payjoin/bin/test_bitcoin --list_content
./build-payjoin-integration/bin/test_payjoin_integration --list_content
ctest --test-dir build-payjoin-integration -N -L payjoin_integration
git diff HEAD --check
python3 test/lint/lint-locale-dependence.py
cargo run --manifest-path test/lint/test_runner/Cargo.toml
```

Require successful exits; ordinary tests report `No errors detected`, integration CTest `100% tests passed`.
Use [lint dependencies](../test/lint/README.md#dependencies) and LF snapshots with Git modes intact;
report skips, external and submodule failures.

## Components

`SenderManager` owns serial execution and services per wallet load. `SenderService` manages
payments, reservations, signing and publication. `SenderSession` wraps protocol and journal
transitions through Rust FFI; transport performs HTTP requests and reports delivery.

## CI

CI prepares both FFI packages and CLI, then production `all`, full CTest and integration.
Setup, discovery, empty selections and failed cases stop CI; test cases are not retried.
Mandatory functional CSV must show `Passed`; `Skipped` fails.
See [CI prerequisites](../ci/README.md#running-a-stage-locally).

```sh
FILE_ENV=ci/test/00_setup_env_native_payjoin.sh ./ci/test_run_all.sh
```
