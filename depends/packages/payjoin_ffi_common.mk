$(package)_version=$(payjoin_ffi_details_version)
$(package)_local_dir=$(payjoin_ffi_details_local_dir)
$(package)_dependencies=native_payjoin_bindgen
$(package)_patches_path := $(BASEDIR)/packages
$(package)_patches = PayjoinFFIConfig.cmake
$(package)_cargo_target_dir ?= $(payjoin_ffi_details_cargo_target_dir)
$(package)_install_prefix=$($(package)_staging_prefix_dir)$($(package)_install_subdir)

define $(package)_preprocess_cmds
  cp -f Cargo-recent.lock Cargo.lock
endef

define $(package)_config_cmds
  test "$(host)" = "$(build)" || { echo "Error: $(package) currently supports native builds only" >&2; exit 1; } && \
  command -v cargo >/dev/null 2>&1 || { echo "Error: $(package) requires cargo in PATH" >&2; exit 1; } && \
  command -v rustc >/dev/null 2>&1 || { echo "Error: $(package) requires rustc in PATH" >&2; exit 1; } && \
  rustc_version=$$$$(RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) rustc --version 2>&1) || { echo "Error: failed to run rustc $(payjoin_ffi_details_rust_toolchain): $$$$rustc_version" >&2; exit 1; }; \
  case "$$$$rustc_version" in \
    "rustc $(payjoin_ffi_details_rust_toolchain) "*) ;; \
    *) echo "Error: $(package) requires rustc $(payjoin_ffi_details_rust_toolchain), got: $$$$rustc_version" >&2; exit 1 ;; \
  esac
endef

define $(package)_build_cmds
  RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) \
  CARGO_TARGET_DIR="$($(package)_cargo_target_dir)" \
  cargo build \
    --package payjoin-ffi \
    --lib \
    $($(package)_cargo_opts) \
    --locked \
    --no-default-features && \
  test -s "$($(package)_cargo_target_dir)/$($(package)_cargo_profile)/libpayjoin_ffi.a" && \
  test -s "$($(package)_cargo_target_dir)/$($(package)_cargo_profile)/libpayjoin_ffi.so" && \
  rm -rf "$($(package)_build_dir)/generated-cpp" && \
  mkdir -p "$($(package)_build_dir)/generated-cpp" && \
  cd "$($(package)_build_dir)/payjoin-ffi" && \
  CARGO=$$$$(command -v cargo) \
  RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) \
  UNIFFI_BINDGEN_LANGUAGE=cpp \
  $(build_prefix)/bin/uniffi-bindgen \
    --library "$($(package)_cargo_target_dir)/$($(package)_cargo_profile)/libpayjoin_ffi.so" \
    --out-dir "$($(package)_build_dir)/generated-cpp" \
    --skip-async && \
  test -s "$($(package)_build_dir)/generated-cpp/payjoin.cpp" && \
  test -s "$($(package)_build_dir)/generated-cpp/payjoin.hpp" && \
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
  mkdir -p "$($(package)_install_prefix)/lib/cmake/PayjoinFFI" && \
  mkdir -p "$($(package)_install_prefix)/share/payjoin/cpp" && \
  cp "$($(package)_cargo_target_dir)/$($(package)_cargo_profile)/libpayjoin_ffi.a" "$($(package)_install_prefix)/lib/" && \
  sed 's/@PAYJOIN_FFI_TEST_UTILS@/$($(package)_test_utils)/g' "$($(package)_patch_dir)/PayjoinFFIConfig.cmake" > \
    "$($(package)_install_prefix)/lib/cmake/PayjoinFFI/PayjoinFFIConfig.cmake" && \
  cp "$($(package)_build_dir)/generated-cpp/"* "$($(package)_install_prefix)/share/payjoin/cpp/"
endef
