/*-------------------------------------------------------------------------
 *
 * file_encryption_load.h
 *	  Dynamic-load helper for file encryption modules.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/common/file_encryption_load.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef FILE_ENCRYPTION_LOAD_H
#define FILE_ENCRYPTION_LOAD_H

#include "common/file_encryption_module.h"

extern bool load_file_encryption_module(const char *my_exec_path,
										const char *libname,
										const char *config,
										void **handle_out,
										const FileEncryptionCallbacks **callbacks_out,
										char **errmsg);

#endif							/* FILE_ENCRYPTION_LOAD_H */
