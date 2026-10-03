package=payjoin_ffi
include packages/payjoin_ffi_details.mk
$(package)_cargo_profile=release
$(package)_cargo_opts=--release
$(package)_test_utils=FALSE
include packages/payjoin_ffi_common.mk
