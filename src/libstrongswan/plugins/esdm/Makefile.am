AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	$(esdm_rpc_client_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-esdm.la
else
plugin_LTLIBRARIES = libstrongswan-esdm.la
endif

libstrongswan_esdm_la_SOURCES = \
	esdm_plugin.h esdm_plugin.c \
	esdm_rng.c esdm_rng.h

libstrongswan_esdm_la_LDFLAGS = -module -avoid-version
libstrongswan_esdm_la_LIBADD  = $(esdm_rpc_client_LIBS)
