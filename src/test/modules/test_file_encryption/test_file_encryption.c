/*-------------------------------------------------------------------------
 *
 * test_file_encryption.c
 *	  Test module for file encryption callbacks.
 *
 * Implements a tiny path-keyed XOR transform — symmetric, so encrypt and
 * decrypt are the same code path.  No real security; just a way to
 * exercise every code path that touches the encryption module.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/test/modules/test_file_encryption/test_file_encryption.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "common/file_encryption_module.h"
#include "fmgr.h"
#include "port.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

typedef struct TestFileEncryptionState
{
	uint64		encrypt_calls;
	uint64		decrypt_calls;
	uint64		encrypt_bytes;
	uint64		decrypt_bytes;
} TestFileEncryptionState;

static void test_file_encryption_startup(FileEncryptionModuleState *state);
static void test_file_encryption_shutdown(FileEncryptionModuleState *state);
static void test_file_encryption_encrypt(const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);
static void test_file_encryption_decrypt(const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);

static const FileEncryptionCallbacks test_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.overhead_size = 0,			/* size-preserving XOR; no per-call overhead */

	.startup_cb = test_file_encryption_startup,
	.shutdown_cb = test_file_encryption_shutdown,
	.encrypt_cb = test_file_encryption_encrypt,
	.decrypt_cb = test_file_encryption_decrypt,
};

static bool log_summary = false;

/*
 * Optional tampering of decrypt output to exercise the validation paths in
 * callers.  The default ("none") is a transparent round-trip.
 */
typedef enum
{
	TAMPER_NONE,
	TAMPER_DECRYPT_SHORT,		/* return one byte less than expected */
}			TamperMode;

static int	tamper_mode = TAMPER_NONE;

static const struct config_enum_entry tamper_mode_options[] = {
	{"none", TAMPER_NONE, false},
	{"decrypt_short", TAMPER_DECRYPT_SHORT, false},
	{NULL, 0, false}
};

static uint32
path_hash(const char *path)
{
	uint32		hash = 5381;

	while (*path)
		hash = (hash << 5) + hash + (unsigned char) *path++;

	return hash;
}

/*
 * Symmetric XOR keystream derived from path + file_offset, written into
 * dst.  Used for both encrypt and decrypt.
 */
static void
xor_transform(const char *path, uint64 file_offset,
			  const char *data, Size data_len, StringInfo dst)
{
	uint32		hash = path_hash(path);
	Size		i;

	enlargeStringInfo(dst, data_len);
	memcpy(dst->data, data, data_len);
	dst->len = data_len;
	dst->data[dst->len] = '\0';

	for (i = 0; i < data_len; i++)
	{
		uint8		mask = (uint8) (hash + file_offset + i);

		dst->data[i] ^= mask;
	}
}

/*
 * Module entry point.  This module does no real cryptography, so it
 * ignores 'config' entirely; the per-module GUCs below carry whatever
 * runtime knobs the test scripts twiddle.
 */
bool
_PG_file_encryption_module_init(const char *config,
								const FileEncryptionCallbacks **callbacks_out,
								char **errmsg)
{
	DefineCustomBoolVariable("test_file_encryption.log_summary",
							 "Log callback activity when a backend exits.",
							 NULL,
							 &log_summary,
							 false,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	DefineCustomEnumVariable("test_file_encryption.tamper_mode",
							 "Deliberately corrupt decrypt output to exercise validation.",
							 NULL,
							 &tamper_mode,
							 TAMPER_NONE,
							 tamper_mode_options,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	MarkGUCPrefixReserved("test_file_encryption");

	*callbacks_out = &test_file_encryption_callbacks;
	return true;
}

static void
test_file_encryption_startup(FileEncryptionModuleState *state)
{
	TestFileEncryptionState *private_state;

	private_state = palloc0_object(TestFileEncryptionState);
	state->private_data = private_state;
}

static void
test_file_encryption_shutdown(FileEncryptionModuleState *state)
{
	TestFileEncryptionState *private_state;

	private_state = (TestFileEncryptionState *) state->private_data;

	if (log_summary && private_state != NULL)
		elog(LOG,
			 "test_file_encryption: encrypt_calls=" UINT64_FORMAT " decrypt_calls=" UINT64_FORMAT
			 " encrypt_bytes=" UINT64_FORMAT " decrypt_bytes=" UINT64_FORMAT,
			 private_state->encrypt_calls,
			 private_state->decrypt_calls,
			 private_state->encrypt_bytes,
			 private_state->decrypt_bytes);
}

static void
test_file_encryption_encrypt(const FileEncryptionModuleState *state,
							 const char *path, uint64 file_offset,
							 const char *data, Size data_len,
							 StringInfo dst)
{
	TestFileEncryptionState *private_state;

	private_state = (TestFileEncryptionState *) state->private_data;
	xor_transform(path, file_offset, data, data_len, dst);
	private_state->encrypt_calls++;
	private_state->encrypt_bytes += data_len;
}

static void
test_file_encryption_decrypt(const FileEncryptionModuleState *state,
							 const char *path, uint64 file_offset,
							 const char *data, Size data_len,
							 StringInfo dst)
{
	TestFileEncryptionState *private_state;

	private_state = (TestFileEncryptionState *) state->private_data;
	xor_transform(path, file_offset, data, data_len, dst);
	private_state->decrypt_calls++;
	private_state->decrypt_bytes += data_len;

	switch (tamper_mode)
	{
		case TAMPER_NONE:
			break;
		case TAMPER_DECRYPT_SHORT:
			/* drop one byte so plaintext_size mismatches */
			if (dst->len > 0)
			{
				dst->len--;
				dst->data[dst->len] = '\0';
			}
			break;
	}
}
