# contrib/basic_file_encryption/Makefile

MODULE_big = basic_file_encryption
OBJS = \
	$(WIN32RES) \
	basic_file_encryption.o
PGFILEDESC = "basic_file_encryption - reference file encryption module"

NO_INSTALLCHECK = 1
TAP_TESTS = 1

# Link against libcrypto for AES-GCM support.
SHLIB_LINK += $(filter -lcrypto, $(LIBS))

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/basic_file_encryption
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
