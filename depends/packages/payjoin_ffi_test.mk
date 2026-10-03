package=payjoin_ffi_test
include packages/payjoin_ffi_details.mk
$(package)_cargo_profile=debug
$(package)_cargo_opts=--features cpp,_test-utils
$(package)_cargo_target_dir=$(base_build_dir)/$(host)/payjoin-cargo-test-target
$(package)_install_subdir=/tests/payjoin-ffi
$(package)_test_utils=TRUE
include packages/payjoin_ffi_common.mk
