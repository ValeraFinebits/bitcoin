package=native_payjoin_bindgen
include packages/payjoin_ffi_details.mk

$(package)_version=$(payjoin_ffi_details_version)
$(package)_local_dir=$(payjoin_ffi_details_local_dir)

define $(package)_preprocess_cmds
  cp -f Cargo-recent.lock Cargo.lock
endef

define $(package)_config_cmds
  command -v cargo >/dev/null 2>&1 || { echo "Error: native_payjoin_bindgen requires cargo in PATH" >&2; exit 1; } && \
  command -v rustc >/dev/null 2>&1 || { echo "Error: native_payjoin_bindgen requires rustc in PATH" >&2; exit 1; } && \
  rustc_version=$$$$(RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) rustc --version 2>&1) || { echo "Error: failed to run rustc $(payjoin_ffi_details_rust_toolchain): $$$$rustc_version" >&2; exit 1; }; \
  case "$$$$rustc_version" in \
    "rustc $(payjoin_ffi_details_rust_toolchain) "*) ;; \
    *) echo "Error: native_payjoin_bindgen requires rustc $(payjoin_ffi_details_rust_toolchain), got: $$$$rustc_version" >&2; exit 1 ;; \
  esac
endef

define $(package)_build_cmds
  RUSTUP_TOOLCHAIN=$(payjoin_ffi_details_rust_toolchain) \
  CARGO_TARGET_DIR="$(payjoin_ffi_details_cargo_target_dir)" \
  cargo build \
    --package payjoin-ffi \
    --bin uniffi-bindgen \
    --release \
    --locked \
    --no-default-features \
    --features cpp && \
  test -s "$(payjoin_ffi_details_cargo_target_dir)/release/uniffi-bindgen"
endef

define $(package)_stage_cmds
  mkdir -p "$($(package)_staging_prefix_dir)/bin" && \
  cp "$(payjoin_ffi_details_cargo_target_dir)/release/uniffi-bindgen" \
    "$($(package)_staging_prefix_dir)/bin/uniffi-bindgen" && \
  chmod 755 "$($(package)_staging_prefix_dir)/bin/uniffi-bindgen"
endef
