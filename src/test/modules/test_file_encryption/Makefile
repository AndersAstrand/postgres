#-------------------------------------------------------------------------
#
# Makefile for src/test/modules/test_file_encryption
#
# Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
# Portions Copyright (c) 1994, Regents of the University of California
#
#-------------------------------------------------------------------------

MODULES = test_file_encryption
PGFILEDESC = "test_file_encryption - test file encryption module"

NO_INSTALLCHECK = 1
TAP_TESTS = 1

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_file_encryption
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
