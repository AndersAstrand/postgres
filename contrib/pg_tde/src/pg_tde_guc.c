/*-------------------------------------------------------------------------
 *
 * pg_tde_guc.c
 *	  GUC variables for pg_tde
 *
 *
 * IDENTIFICATION
 *	  src/pg_tde_guc.c
 *
 *-------------------------------------------------------------------------
 */

#include "pg_tde_guc.h"
#include "postgres.h"
#include "utils/guc.h"

#ifndef FRONTEND

bool		AllowInheritGlobalProviders = true;
bool		EncryptXLog = false;
bool		EnforceEncryption = false;
char	   *KeyringFileLocation = NULL;

void
TdeGucInit(void)
{
	DefineCustomBoolVariable("pg_tde.inherit_global_providers", /* name */
							 "Allow using global key providers for databases.", /* short_desc */
							 NULL,	/* long_desc */
							 &AllowInheritGlobalProviders,	/* value address */
							 true,	/* boot value */
							 PGC_SUSET, /* context */
							 0, /* flags */
							 NULL,	/* check_hook */
							 NULL,	/* assign_hook */
							 NULL	/* show_hook */
		);

	DefineCustomBoolVariable("pg_tde.wal_encrypt",	/* name */
							 "Enable/Disable encryption of WAL.",	/* short_desc */
							 NULL,	/* long_desc */
							 &EncryptXLog,	/* value address */
							 false, /* boot value */
							 PGC_POSTMASTER,	/* context */
							 0, /* flags */
							 NULL,	/* check_hook */
							 NULL,	/* assign_hook */
							 NULL	/* show_hook */
		);

	DefineCustomBoolVariable("pg_tde.enforce_encryption",	/* name */
							 "Only allow the creation of encrypted tables.",	/* short_desc */
							 NULL,	/* long_desc */
							 &EnforceEncryption,	/* value address */
							 false, /* boot value */
							 PGC_SUSET, /* context */
							 0, /* flags */
							 NULL,	/* check_hook */
							 NULL,	/* assign_hook */
							 NULL	/* show_hook */
		);

	DefineCustomStringVariable("pg_tde.keyring_file_location",	/* name */
							   "Only allow keyring files under this path.",	/* short_desc */
							   NULL,	/* long_desc */
							   &KeyringFileLocation,	/* value address */
							   NULL, /* boot value */
							   PGC_SUSET, /* context */
							   0, /* flags */
							   NULL, //CheckKeyringFileLocation,	/* check_hook */
							   NULL,	/* assign_hook */
							   NULL	/* show_hook */
		);

}

#endif

pg_tde keyring