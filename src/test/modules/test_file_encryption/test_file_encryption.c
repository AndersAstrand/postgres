/*-------------------------------------------------------------------------
 *
 * test_file_encryption.c
 *	  Test module for file encryption callbacks.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/test/modules/test_file_encryption/test_file_encryption.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "fmgr.h"
#include "port.h"
#include "storage/file_encryption.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

/*
 * Per-file header: a 4-byte magic plus a 12-byte random salt.  The salt
 * mixes into the XOR keystream so a record's ciphertext depends on which
 * file it was written into.
 */
#define TFE_HEADER_MAGIC	0x54464531	/* "TFE1" */
#define TFE_SALT_LEN		12
#define TFE_HEADER_SIZE		(sizeof(uint32) + TFE_SALT_LEN)

typedef struct TestFileEncryptionState
{
	uint64		encrypt_calls;
	uint64		decrypt_calls;
	uint64		encrypt_bytes;
	uint64		decrypt_bytes;
	uint64		init_files;
	uint64		open_files;
} TestFileEncryptionState;

typedef struct TestFilePrivate
{
	unsigned char salt[TFE_SALT_LEN];
} TestFilePrivate;

static void test_file_encryption_startup(FileEncryptionModuleState *state);
static void test_file_encryption_shutdown(FileEncryptionModuleState *state);
static void test_file_encryption_init_file(const FileEncryptionModuleState *state,
										   FileEncryptionFileState *fstate,
										   const char *path,
										   char *header);
static void test_file_encryption_open_file(const FileEncryptionModuleState *state,
										   FileEncryptionFileState *fstate,
										   const char *path,
										   const char *header);
static void test_file_encryption_close_file(const FileEncryptionModuleState *state,
											FileEncryptionFileState *fstate);
static void test_file_encryption_encrypt(const FileEncryptionModuleState *state,
										 FileEncryptionFileState *fstate,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);
static void test_file_encryption_decrypt(const FileEncryptionModuleState *state,
										 FileEncryptionFileState *fstate,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 StringInfo dst);

static const FileEncryptionCallbacks test_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.file_header_size = TFE_HEADER_SIZE,

	.startup_cb = test_file_encryption_startup,
	.shutdown_cb = test_file_encryption_shutdown,
	.init_file_cb = test_file_encryption_init_file,
	.open_file_cb = test_file_encryption_open_file,
	.close_file_cb = test_file_encryption_close_file,
	.encrypt_cb = test_file_encryption_encrypt,
	.decrypt_cb = test_file_encryption_decrypt
};

static bool log_summary = false;

static uint32
path_hash(const char *path)
{
	uint32		hash = 5381;

	while (*path)
		hash = (hash << 5) + hash + (unsigned char) *path++;

	return hash;
}

static void
xor_transform(const TestFilePrivate *priv, const char *path, uint64 file_offset,
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

		mask ^= priv->salt[i % TFE_SALT_LEN];
		dst->data[i] ^= mask;
	}
}

void
_PG_init(void)
{
	DefineCustomBoolVariable("test_file_encryption.log_summary",
							 "Log callback activity when a backend exits.",
							 NULL,
							 &log_summary,
							 false,
							 PGC_SIGHUP,
							 0,
							 NULL, NULL, NULL);

	MarkGUCPrefixReserved("test_file_encryption");
}

const FileEncryptionCallbacks *
_PG_file_encryption_module_init(void)
{
	return &test_file_encryption_callbacks;
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
			 " encrypt_bytes=" UINT64_FORMAT " decrypt_bytes=" UINT64_FORMAT
			 " init_files=" UINT64_FORMAT " open_files=" UINT64_FORMAT,
			 private_state->encrypt_calls,
			 private_state->decrypt_calls,
			 private_state->encrypt_bytes,
			 private_state->decrypt_bytes,
			 private_state->init_files,
			 private_state->open_files);
}

static void
test_file_encryption_init_file(const FileEncryptionModuleState *state,
							   FileEncryptionFileState *fstate,
							   const char *path,
							   char *header)
{
	TestFileEncryptionState *private_state;
	TestFilePrivate *priv;
	uint32		magic = TFE_HEADER_MAGIC;

	priv = palloc0_object(TestFilePrivate);

	if (!pg_strong_random(priv->salt, sizeof(priv->salt)))
		elog(ERROR, "test_file_encryption: could not generate salt for \"%s\"",
			 path);

	memcpy(header, &magic, sizeof(magic));
	memcpy(header + sizeof(magic), priv->salt, sizeof(priv->salt));

	fstate->private_data = priv;

	private_state = (TestFileEncryptionState *) state->private_data;
	private_state->init_files++;
}

static void
test_file_encryption_open_file(const FileEncryptionModuleState *state,
							   FileEncryptionFileState *fstate,
							   const char *path,
							   const char *header)
{
	TestFileEncryptionState *private_state;
	TestFilePrivate *priv;
	uint32		magic;

	memcpy(&magic, header, sizeof(magic));
	if (magic != TFE_HEADER_MAGIC)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("test_file_encryption: bad header magic in \"%s\"",
						path),
				 errdetail("Expected %#x, got %#x.",
						   TFE_HEADER_MAGIC, magic)));

	priv = palloc0_object(TestFilePrivate);
	memcpy(priv->salt, header + sizeof(magic), sizeof(priv->salt));
	fstate->private_data = priv;

	private_state = (TestFileEncryptionState *) state->private_data;
	private_state->open_files++;
}

static void
test_file_encryption_close_file(const FileEncryptionModuleState *state,
								FileEncryptionFileState *fstate)
{
	if (fstate->private_data != NULL)
	{
		pfree(fstate->private_data);
		fstate->private_data = NULL;
	}
}

static void
test_file_encryption_encrypt(const FileEncryptionModuleState *state,
							 FileEncryptionFileState *fstate,
							 const char *path, uint64 file_offset,
							 const char *data, Size data_len,
							 StringInfo dst)
{
	TestFileEncryptionState *private_state;
	TestFilePrivate *priv = (TestFilePrivate *) fstate->private_data;

	private_state = (TestFileEncryptionState *) state->private_data;
	xor_transform(priv, path, file_offset, data, data_len, dst);
	private_state->encrypt_calls++;
	private_state->encrypt_bytes += data_len;
}

static void
test_file_encryption_decrypt(const FileEncryptionModuleState *state,
							 FileEncryptionFileState *fstate,
							 const char *path, uint64 file_offset,
							 const char *data, Size data_len,
							 StringInfo dst)
{
	TestFileEncryptionState *private_state;
	TestFilePrivate *priv = (TestFilePrivate *) fstate->private_data;

	private_state = (TestFileEncryptionState *) state->private_data;
	xor_transform(priv, path, file_offset, data, data_len, dst);
	private_state->decrypt_calls++;
	private_state->decrypt_bytes += data_len;
}
