# Payjoin tests with upstream TestServices

Native Linux tests use Core's in-process regtest wallets and actual upstream
TestServices, without an external bitcoind or a replacement SenderSession.

| Build tree / executable | Suites | Rust FFI |
| --- | --- | --- |
| `build-payjoin/bin/test_bitcoin` | payjoin_tests, payjoin_sender_tests, payjoin_transport_tests | Production depends package; no _test-utils |
| `build-payjoin-integration/bin/test_payjoin_integration` | payjoin_integration_tests | Separate _test-utils library and matching generated C++ |

Use separate build trees and FFI packages. The integration build selects test FFI
before compiling wallet/adapter code; CMake rejects mixing test and production FFI.
Pre-exchange tests hold requests without starting TestServices; HTTP-only cases
need no wallet fixture. Receiver Progress establishes actual observation of original;
transport acceptance, HTTP submission and delivery of a response are separate stages.

## Build and run

Run from the source root with CMake 3.24 or newer. The commands use depends curl
and OpenSSL; without depends, curl development version 8.22 or newer is required.
This workflow supports Linux, including Ubuntu WSL, rather than a Windows cross-build.

```sh
source_dir="$PWD"
depends_prefix="$source_dir/depends/$(./depends/config.guess)"
make -C depends -j4 PAYJOIN=1 PAYJOIN_TESTS=1 NO_QT=1 NO_IPC=1 NO_ZMQ=1 NO_USDT=1
cmake -S . -B build-payjoin \
  --toolchain "$depends_prefix/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_PAYJOIN=ON -DBUILD_TESTS=ON \
  -DBUILD_PAYJOIN_INTEGRATION_TESTS=OFF -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
  -DPayjoinFFI_DIR="$depends_prefix/lib/cmake/PayjoinFFI"
cmake --build build-payjoin --target test_bitcoin -j4
./build-payjoin/bin/test_bitcoin \
  --run_test=payjoin_tests,payjoin_sender_tests,payjoin_transport_tests \
  --catch_system_error=no --log_level=test_suite
```

Both FFI packages use the installed Rust 1.85.1 toolchain, Cargo-recent.lock,
`--locked` and the pinned native C++ generator. `payjoin_ffi` uses release without
_test-utils; `payjoin_ffi_test` uses dev/debug with cpp,_test-utils. They share a
recipe and use separate Cargo target directories. The generator keeps its
existing release profile and production Cargo directory.

Prepare both packages before configuring either Core tree. The first invocation
may download locked dependencies; after filling the cache, use
`CARGO_NET_OFFLINE=true` with the same depends command for offline preparation.
Running depends again can recreate its prefix, so do not run it between the two
Core passes.

```sh
cmake -S . -B build-payjoin-integration \
  --toolchain "$depends_prefix/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
  -DENABLE_PAYJOIN=ON -DBUILD_TESTS=ON \
  -DBUILD_PAYJOIN_INTEGRATION_TESTS=ON \
  -DPayjoinFFI_DIR="$depends_prefix/tests/payjoin-ffi/lib/cmake/PayjoinFFI"
cmake --build build-payjoin-integration --target test_payjoin_integration -j4
ctest --test-dir build-payjoin-integration \
  -L payjoin_integration --output-on-failure --no-tests=error -j1
```

Production FFI is installed under the depends prefix; test FFI is under
`tests/payjoin-ffi`, each with `lib/libpayjoin_ffi.a`, a CMake config under
`lib/cmake/PayjoinFFI` and bindings under `share/payjoin/cpp`. The test executable
links one static FFI archive. The Rust .so is only an intermediate for binding
generation; no Payjoin loader environment is needed.

The toolchain in these examples selects all depends libraries and is used by CI.
Core can instead use system dependencies and a separately prepared FFI package:
omit `--toolchain` and set `PayjoinFFI_DIR` to the appropriate config directory.
CMake rejects the test package when integration is off, and the production
package when integration is on. Missing bindings fail package validation or
compilation.

## Process lifetime and CI

CTest discovers cases from the compiled Boost listing and runs each integration
case in a separate process with a 120-second timeout. Upstream TestServices has a
global Tokio runtime without shutdown: dropping its C++ handle does not abort
spawned tasks. Process exit stops the threads/listeners; no child bitcoind is used.
Keep the per-case process isolation and bounded HTTP/receiver waits.

The existing native Payjoin job first prepares both FFI packages in depends.
A failure preparing the test package stops the job before the ordinary pass.
The ordinary `all` build and full CTest set use production FFI; the second Core
tree selects the test package and runs the integration label. Both passes use
Rust 1.85.1 and the depends toolchain. Depends is not rerun between them. Discovery failure, empty selection
or a failed case fails the job; cases are not automatically retried.

```sh
FILE_ENV=ci/test/00_setup_env_native_payjoin.sh ./ci/test_run_all.sh
```

For a clean CI check, use an LF source snapshot with Git modes preserved and new
build/cache directories. Keep development caches intact: Docker `--no-cache` does
not clear named cache volumes. Downloaded dependency sources may be reused.

## Verification

Rebuild after changing cases and obtain counts from the executable and CTest:

```sh
./build-payjoin/bin/test_bitcoin --list_content
./build-payjoin-integration/bin/test_payjoin_integration --list_content
ctest --test-dir build-payjoin-integration -N -L payjoin_integration
git diff HEAD --check
python3 test/lint/lint-locale-dependence.py
cargo run --manifest-path test/lint/test_runner/Cargo.toml
```

Require successful exits, `No errors detected` from ordinary tests and
`100% tests passed` from integration CTest. Run full lint with its required tools
in a matching LF snapshot; make new files visible in that snapshot's index while
preserving the original index. Report skipped checks and external/submodule
failures separately from build/test results.
