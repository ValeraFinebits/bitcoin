packages:=

boost_packages = boost

qrencode_linux_packages = qrencode
qrencode_freebsd_packages = qrencode
qrencode_openbsd_packages = qrencode
qrencode_darwin_packages = qrencode
qrencode_mingw32_packages = qrencode

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_cursor libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm
qt_freebsd_packages:=$(qt_linux_packages)
qt_openbsd_packages:=$(qt_linux_packages)
qt_darwin_packages=qt
qt_mingw32_packages=qt
ifneq ($(host),$(build))
qt_native_packages := native_qt
endif

sqlite_packages=sqlite

zmq_packages=zeromq

ipc_packages = capnp
multiprocess_native_packages = native_libmultiprocess native_capnp

usdt_linux_packages=systemtap

# depends requires transitive packages to be registered as well.
payjoin_linux_packages=payjoin_ffi curl openssl
payjoin_linux_native_packages=native_payjoin_bindgen

ifneq ($(PAYJOIN_TESTS),)
ifneq ($(PAYJOIN_TESTS),1)
$(error PAYJOIN_TESTS must be empty or 1)
endif
ifneq ($(PAYJOIN),1)
$(error PAYJOIN_TESTS=1 requires PAYJOIN=1)
endif
payjoin_linux_packages+=payjoin_ffi_test
endif
