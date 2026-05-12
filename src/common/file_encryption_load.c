/*-------------------------------------------------------------------------
 *
 * file_encryption_load.c
 *	  Dynamic-load helper for file encryption modules.
 *
 * Both the backend's loader (process_file_encryption_library) and any
 * frontend tool that wants to decrypt/encrypt cluster files use the same
 * module ABI defined in common/file_encryption_module.h.  The backend
 * has its own dlopen plumbing (load_external_function) wired up to
 * dynamic_loader.c; this file gives frontend tools an equivalent
 * libpgcommon-safe entry point.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/common/file_encryption_load.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#ifdef WIN32
#include "port/win32_port.h"	/* for dlopen/dlsym/dlerror */
#else
#include <dlfcn.h>
#endif

#include "common/file_encryption_module.h"
#include "common/file_encryption_load.h"

/*
 * Resolve $libdir/<libname><DLSUFFIX>, dlopen it, look up the module's
 * init symbol, and invoke it with the supplied config string.
 *
 * On success returns true; *handle_out receives the dlopen handle (the
 * caller may pass it to dlclose at shutdown), *callbacks_out receives the
 * module's callback table.
 *
 * On failure returns false and sets *errmsg to a pg_malloc()'d / palloc()'d
 * error string (the caller frees it with pfree/pg_free).
 */
bool
load_file_encryption_module(const char *my_exec_path,
							const char *libname,
							const char *config,
							void **handle_out,
							const FileEncryptionCallbacks **callbacks_out,
							char **errmsg)
{
	char		libdir[MAXPGPATH];
	char		path[MAXPGPATH];
	void	   *handle;
	FileEncryptionModuleInit init;
	char	   *module_errmsg = NULL;

	*handle_out = NULL;

	if (libname == NULL || libname[0] == '\0')
	{
		*errmsg = pstrdup("file encryption library name is empty");
		return false;
	}

	get_pkglib_path(my_exec_path, libdir);
	snprintf(path, sizeof(path), "%s/%s%s", libdir, libname, DLSUFFIX);

	handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL)
	{
		const char *dlerr = dlerror();

		*errmsg = psprintf("could not load file encryption module \"%s\": %s",
						   path, dlerr ? dlerr : "(no dlerror)");
		return false;
	}

	init = (FileEncryptionModuleInit)
		dlsym(handle, "_PG_file_encryption_module_init");
	if (init == NULL)
	{
		const char *dlerr = dlerror();

		*errmsg = psprintf("file encryption module \"%s\" lacks symbol _PG_file_encryption_module_init: %s",
						   path, dlerr ? dlerr : "(no dlerror)");
		dlclose(handle);
		return false;
	}

	if (!(*init) (config, callbacks_out, &module_errmsg))
	{
		*errmsg = psprintf("file encryption module \"%s\" failed to initialize: %s",
						   libname,
						   module_errmsg ? module_errmsg : "(no module errmsg)");
		if (module_errmsg)
			pfree(module_errmsg);
		dlclose(handle);
		return false;
	}

	if (*callbacks_out == NULL ||
		(*callbacks_out)->magic != PG_FILE_ENCRYPTION_MAGIC)
	{
		*errmsg = psprintf("file encryption module \"%s\" returned an incompatible ABI",
						   libname);
		dlclose(handle);
		return false;
	}

	*handle_out = handle;
	return true;
}
