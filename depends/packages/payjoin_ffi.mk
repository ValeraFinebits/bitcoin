package=payjoin_ffi
include packages/payjoin_ffi_details.mk
$(package)_version=$(payjoin_ffi_details_version)
$(package)_local_dir=$(payjoin_ffi_details_local_dir)
$(package)_dependencies=native_payjoin_bindgen
$(package)_patches_path := $(BASEDIR)/packages
$(package)_patches = PayjoinFFIConfig.cmake

ifneq ($(host_os),linux)
$(error payjoin_ffi currently supports Linux only)
endif
ifneq ($(host),$(build))
$(error payjoin_ffi currently supports native builds only)
endif

define $(package)_preprocess_cmds
  cp -f Cargo-recent.lock Cargo.lock
endef

define $(package)_config_cmds
  command -v cargo >/dev/null 2>&1 || { echo "Error: payjoin_ffi requires cargo in PATH" >&2; exit 1; } && \
  command -v rustc >/dev/null 2>&1 || { echo "Error: payjoin_ffi requires rustc in PATH" >&2; exit 1; } && \
  rustc_version=$$$$(RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) rustc --version 2>&1) || { echo "Error: failed to run rustc $(payjoin_ffi_details_rust_toolchain): $$$$rustc_version" >&2; exit 1; }; \
  case "$$$$rustc_version" in \
    "rustc $(payjoin_ffi_details_rust_toolchain) "*) ;; \
    *) echo "Error: payjoin_ffi requires rustc $(payjoin_ffi_details_rust_toolchain), got: $$$$rustc_version" >&2; exit 1 ;; \
  esac
endef

define $(package)_build_cmds
  RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) \
  CARGO_TARGET_DIR="$(payjoin_ffi_details_cargo_target_dir)" \
  cargo build \
    --package payjoin-ffi \
    --lib \
    --release \
    --locked \
    --no-default-features && \
  test -s "$(payjoin_ffi_details_cargo_target_dir)/release/libpayjoin_ffi.a" && \
  test -s "$(payjoin_ffi_details_cargo_target_dir)/release/libpayjoin_ffi.so" && \
  rm -rf "$($(package)_build_dir)/generated-cpp" && \
  mkdir -p "$($(package)_build_dir)/generated-cpp" && \
  cd "$($(package)_build_dir)/payjoin-ffi" && \
  CARGO=$$$$(command -v cargo) \
  RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) \
  UNIFFI_BINDGEN_LANGUAGE=cpp \
  $(build_prefix)/bin/uniffi-bindgen \
    --library "$(payjoin_ffi_details_cargo_target_dir)/release/libpayjoin_ffi.so" \
    --out-dir "$($(package)_build_dir)/generated-cpp" \
    --skip-async && \
  test -f "$($(package)_build_dir)/generated-cpp/payjoin.cpp" && \
  test -s "$($(package)_build_dir)/generated-cpp/payjoin.cpp" && \
  test -f "$($(package)_build_dir)/generated-cpp/payjoin.hpp" && \
  test -s "$($(package)_build_dir)/generated-cpp/payjoin.hpp" && \
  test -f "$($(package)_build_dir)/generated-cpp/payjoin_scaffolding.hpp" && \
  test -s "$($(package)_build_dir)/generated-cpp/payjoin_scaffolding.hpp" && \
  find "$($(package)_build_dir)/generated-cpp" -mindepth 1 \
    ! -path "$($(package)_build_dir)/generated-cpp/payjoin.cpp" \
    ! -path "$($(package)_build_dir)/generated-cpp/payjoin.hpp" \
    ! -path "$($(package)_build_dir)/generated-cpp/payjoin_scaffolding.hpp" \
    -exec false {} + && \
  grep -Fq '#include "payjoin.hpp"' \
    "$($(package)_build_dir)/generated-cpp/payjoin.cpp" && \
  grep -Fq '#include "payjoin_scaffolding.hpp"' \
    "$($(package)_build_dir)/generated-cpp/payjoin.hpp"
endef

define $(package)_stage_cmds
  test -f "$(payjoin_ffi_details_cargo_target_dir)/release/libpayjoin_ffi.a" && \
  test -s "$(payjoin_ffi_details_cargo_target_dir)/release/libpayjoin_ffi.a" && \
  mkdir -p "$($(package)_staging_prefix_dir)/lib/cmake/PayjoinFFI" && \
  mkdir -p "$($(package)_staging_prefix_dir)/share/payjoin/cpp" && \
  cp "$(payjoin_ffi_details_cargo_target_dir)/release/libpayjoin_ffi.a" "$($(package)_staging_prefix_dir)/lib/" && \
  cp "$($(package)_patch_dir)/PayjoinFFIConfig.cmake" \
    "$($(package)_staging_prefix_dir)/lib/cmake/PayjoinFFI/PayjoinFFIConfig.cmake" && \
  cp "$($(package)_build_dir)/generated-cpp/payjoin.cpp" \
    "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.cpp" && \
  cp "$($(package)_build_dir)/generated-cpp/payjoin.hpp" \
    "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.hpp" && \
  cp "$($(package)_build_dir)/generated-cpp/payjoin_scaffolding.hpp" \
    "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin_scaffolding.hpp" && \
  test -f "$($(package)_staging_prefix_dir)/lib/libpayjoin_ffi.a" && \
  test -s "$($(package)_staging_prefix_dir)/lib/libpayjoin_ffi.a" && \
  test -f "$($(package)_staging_prefix_dir)/lib/cmake/PayjoinFFI/PayjoinFFIConfig.cmake" && \
  test -s "$($(package)_staging_prefix_dir)/lib/cmake/PayjoinFFI/PayjoinFFIConfig.cmake" && \
  test -f "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.cpp" && \
  test -s "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.cpp" && \
  test -f "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.hpp" && \
  test -s "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.hpp" && \
  test -f "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin_scaffolding.hpp" && \
  test -s "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin_scaffolding.hpp" && \
  find "$($(package)_staging_prefix_dir)" -mindepth 1 \
    ! -path "$($(package)_staging_prefix_dir)/lib" \
    ! -path "$($(package)_staging_prefix_dir)/lib/libpayjoin_ffi.a" \
    ! -path "$($(package)_staging_prefix_dir)/lib/cmake" \
    ! -path "$($(package)_staging_prefix_dir)/lib/cmake/PayjoinFFI" \
    ! -path "$($(package)_staging_prefix_dir)/lib/cmake/PayjoinFFI/PayjoinFFIConfig.cmake" \
    ! -path "$($(package)_staging_prefix_dir)/share" \
    ! -path "$($(package)_staging_prefix_dir)/share/payjoin" \
    ! -path "$($(package)_staging_prefix_dir)/share/payjoin/cpp" \
    ! -path "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.cpp" \
    ! -path "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin.hpp" \
    ! -path "$($(package)_staging_prefix_dir)/share/payjoin/cpp/payjoin_scaffolding.hpp" \
    -exec false {} +
endef
