package=curl
$(package)_version=8.22.0
$(package)_download_path=https://curl.se/download
$(package)_file_name=curl-$($(package)_version).tar.xz
$(package)_sha256_hash=f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7
$(package)_dependencies=openssl
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts=-DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON
  $(package)_config_opts+=-DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DBUILD_EXAMPLES=OFF
  $(package)_config_opts+=-DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF
  $(package)_config_opts+=-DCURL_USE_OPENSSL=ON -DOPENSSL_USE_STATIC_LIBS=TRUE
  $(package)_config_opts+=-DCMAKE_FIND_ROOT_PATH=$(host_prefix)
  $(package)_config_opts+=-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
  $(package)_config_opts+=-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER
  $(package)_config_opts+=-DCURL_USE_PKGCONFIG=OFF
  $(package)_config_opts+=-DHTTP_ONLY=ON -DENABLE_IPV6=ON -DENABLE_THREADED_RESOLVER=ON -DENABLE_ARES=OFF
  $(package)_config_opts+=-DCURL_DISABLE_PROXY=OFF -DCURL_DISABLE_SOCKETPAIR=OFF
  $(package)_config_opts+=-DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF
  $(package)_config_opts+=-DCURL_USE_LIBPSL=OFF -DUSE_LIBIDN2=OFF -DUSE_NGHTTP2=OFF
  $(package)_config_opts+=-DUSE_NGTCP2=OFF -DUSE_QUICHE=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_USE_LIBSSH=OFF
  $(package)_config_opts+=-DCURL_USE_GSSAPI=OFF -DCURL_USE_GSASL=OFF -DCURL_USE_LIBUV=OFF -DCURL_USE_LIBBACKTRACE=OFF
  $(package)_config_opts+=-DCURL_USE_MBEDTLS=OFF -DCURL_USE_WOLFSSL=OFF -DCURL_USE_GNUTLS=OFF -DCURL_USE_RUSTLS=OFF
  $(package)_config_opts+=-DCURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt -DCURL_CA_PATH=none -DCURL_CA_FALLBACK=OFF
  $(package)_config_opts+=-DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
