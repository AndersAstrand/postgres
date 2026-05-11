# contrib/gost_file_encryption/Makefile

MODULE_big = gost_file_encryption
OBJS = \
	$(WIN32RES) \
	gost_file_encryption.o
PGFILEDESC = "gost_file_encryption - GOST reference file encryption module"

NO_INSTALLCHECK = 1
TAP_TESTS = 1

# Link against libcrypto for OpenSSL provider-backed ciphers and HMAC.
SHLIB_LINK += $(filter -lcrypto, $(LIBS))

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/gost_file_encryption
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
