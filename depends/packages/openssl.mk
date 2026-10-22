package=openssl
$(package)_version=4.0.2
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)
$(package)_file_name=openssl-$($(package)_version).tar.gz
$(package)_sha256_hash=736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8

define $(package)_set_vars
  $(package)_config_opts=--prefix=$(host_prefix) --libdir=lib --openssldir=/etc/ssl
  $(package)_config_opts+=no-shared no-module no-apps no-tests no-autoload-config
  # OpenSSL's inline assembly uses GNU C extensions.
  $(package)_cflags+=-std=gnu11 -fPIC
endef

# OpenSSL needs no depends headers; omit that include path from compiler metadata.
define $(package)_config_cmds
  test "$(host)" = "$(build)" && test "$(host_os)" = linux || { echo "OpenSSL depends currently supports native Linux only" >&2; exit 1; }; \
  CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" \
  CFLAGS="$($(package)_cflags)" CPPFLAGS="$(filter-out -I$(host_prefix)/include,$($(package)_cppflags))" LDFLAGS="$($(package)_ldflags)" \
  perl ./Configure $($(package)_config_opts)
endef

# Modules are disabled, but OpenSSL still embeds their directory in diagnostics.
define $(package)_build_cmds
  $(MAKE) MODULESDIR=/usr/lib/ossl-modules build_libs
endef

define $(package)_stage_cmds
  $(MAKE) MODULESDIR=/usr/lib/ossl-modules DESTDIR=$($(package)_staging_dir) install_dev
endef
