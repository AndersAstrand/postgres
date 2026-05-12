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

PG_MODULE_MAGIC;

typedef struct TestFileEncryptionState
{
	uint64		encrypt_calls;
	uint64		decrypt_calls;
	uint64		encrypt_bytes;
	uint64		decrypt_bytes;
} TestFileEncryptionState;

/*
 * Per-relation state: just the relNumber, used as the XOR keystream seed.
 * Doubles as a corruption check at object_open time — generate_object_key_cb
 * wrote relNumber into the KEY fork, so we expect to see it back.
 */
#define TFE_OBJECT_MAGIC	0x54464530	/* "TFE0" */
#define TFE_OBJECT_WRAP_LEN	(sizeof(uint32) + sizeof(uint32))

typedef struct TestFileEncryptionObject
{
	uint32		rel_number;
} TestFileEncryptionObject;

static bool test_file_encryption_startup(FileEncryptionModuleState *state,
										 char **errmsg);
static void test_file_encryption_shutdown(FileEncryptionModuleState *state);
static bool test_file_encryption_encrypt(const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 char *dst, char **errmsg);
static bool test_file_encryption_decrypt(const FileEncryptionModuleState *state,
										 const char *path, uint64 file_offset,
										 const char *data, Size data_len,
										 char *dst, char **errmsg);
static bool test_file_encryption_generate_object_key(FileEncryptionModuleState *state,
													 const RelFileLocator *locator,
													 char *dst, Size dst_max,
													 Size *wrapped_len,
													 char **errmsg);
static void *test_file_encryption_object_open(FileEncryptionModuleState *state,
											  const RelFileLocator *locator,
											  const char *wrapped, Size wrapped_len,
											  char **errmsg);
static void test_file_encryption_object_close(FileEncryptionModuleState *state,
											  void *object_state);
static bool test_file_encryption_encrypt_page(FileEncryptionModuleState *state,
											  void *object_state,
											  ForkNumber fork, BlockNumber blocknum,
											  const char *src, char *dst,
											  char **errmsg);
static bool test_file_encryption_decrypt_page(FileEncryptionModuleState *state,
											  void *object_state,
											  ForkNumber fork, BlockNumber blocknum,
											  const char *src, char *dst,
											  char **errmsg);

static const FileEncryptionCallbacks test_file_encryption_callbacks = {
	PG_FILE_ENCRYPTION_MAGIC,
	.overhead_size = 0,			/* size-preserving XOR; no per-call overhead */
	.page_overhead_size = 0,	/* size-preserving XOR for pages too */

	.startup_cb = test_file_encryption_startup,
	.shutdown_cb = test_file_encryption_shutdown,
	.encrypt_cb = test_file_encryption_encrypt,
	.decrypt_cb = test_file_encryption_decrypt,
	.generate_object_key_cb = test_file_encryption_generate_object_key,
	.object_open_cb = test_file_encryption_object_open,
	.object_close_cb = test_file_encryption_object_close,
	.encrypt_page_cb = test_file_encryption_encrypt_page,
	.decrypt_page_cb = test_file_encryption_decrypt_page,
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
			  const char *data, Size data_len, char *dst)
{
	uint32		hash = path_hash(path);
	Size		i;

	for (i = 0; i < data_len; i++)
	{
		uint8		mask = (uint8) (hash + file_offset + i);

		dst[i] = data[i] ^ mask;
	}
}

/*
 * Module entry point.  This module does no real cryptography and takes no
 * configuration; the test scripts inspect the always-emitted shutdown log
 * line to confirm that callbacks fired.
 */
bool
_PG_file_encryption_module_init(const char *config,
								const FileEncryptionCallbacks **callbacks_out,
								char **errmsg)
{
	*callbacks_out = &test_file_encryption_callbacks;
	return true;
}

static bool
test_file_encryption_startup(FileEncryptionModuleState *state, char **errmsg)
{
	TestFileEncryptionState *private_state;

	private_state = palloc0_object(TestFileEncryptionState);
	state->private_data = private_state;
	return true;
}

static void
test_file_encryption_shutdown(FileEncryptionModuleState *state)
{
	TestFileEncryptionState *private_state;

	private_state = (TestFileEncryptionState *) state->private_data;

	if (private_state != NULL)
		elog(LOG,
			 "test_file_encryption: encrypt_calls=" UINT64_FORMAT " decrypt_calls=" UINT64_FORMAT
			 " encrypt_bytes=" UINT64_FORMAT " decrypt_bytes=" UINT64_FORMAT,
			 private_state->encrypt_calls,
			 private_state->decrypt_calls,
			 private_state->encrypt_bytes,
			 private_state->decrypt_bytes);
}

static bool
test_file_encryption_encrypt(const FileEncryptionModuleState *state,
							 const char *path, uint64 file_offset,
							 const char *data, Size data_len,
							 char *dst, char **errmsg)
{
	TestFileEncryptionState *private_state;

	private_state = (TestFileEncryptionState *) state->private_data;
	xor_transform(path, file_offset, data, data_len, dst);
	private_state->encrypt_calls++;
	private_state->encrypt_bytes += data_len;
	return true;
}

static bool
test_file_encryption_decrypt(const FileEncryptionModuleState *state,
							 const char *path, uint64 file_offset,
							 const char *data, Size data_len,
							 char *dst, char **errmsg)
{
	TestFileEncryptionState *private_state;

	private_state = (TestFileEncryptionState *) state->private_data;
	xor_transform(path, file_offset, data, data_len, dst);
	private_state->decrypt_calls++;
	private_state->decrypt_bytes += data_len;
	return true;
}

/*
 * Per-relation page encryption: zero-overhead XOR.  The "wrapped DEK" is
 * just a magic + the relNumber, so object_open can sanity-check that the
 * KEY fork wasn't shuffled between relations.  Real modules would put
 * actual key material here.
 */
static bool
test_file_encryption_generate_object_key(FileEncryptionModuleState *state,
										 const RelFileLocator *locator,
										 char *dst, Size dst_max,
										 Size *wrapped_len,
										 char **errmsg)
{
	uint32		magic = TFE_OBJECT_MAGIC;
	uint32		rel = (uint32) locator->relNumber;

	if (dst_max < TFE_OBJECT_WRAP_LEN)
	{
		*errmsg = psprintf("test_file_encryption: wrapped-key buffer is %zu bytes, need %zu",
						   dst_max, (Size) TFE_OBJECT_WRAP_LEN);
		return false;
	}

	memcpy(dst, &magic, sizeof(magic));
	memcpy(dst + sizeof(magic), &rel, sizeof(rel));
	*wrapped_len = TFE_OBJECT_WRAP_LEN;
	return true;
}

static void *
test_file_encryption_object_open(FileEncryptionModuleState *state,
								 const RelFileLocator *locator,
								 const char *wrapped, Size wrapped_len,
								 char **errmsg)
{
	TestFileEncryptionObject *obj;
	uint32		magic;
	uint32		rel;

	if (wrapped_len != TFE_OBJECT_WRAP_LEN)
	{
		*errmsg = psprintf("unexpected wrapped object length %zu", wrapped_len);
		return NULL;
	}
	memcpy(&magic, wrapped, sizeof(magic));
	memcpy(&rel, wrapped + sizeof(magic), sizeof(rel));
	if (magic != TFE_OBJECT_MAGIC)
	{
		*errmsg = psprintf("bad object magic 0x%08x", magic);
		return NULL;
	}
	if (rel != (uint32) locator->relNumber)
	{
		*errmsg = psprintf("relNumber mismatch on KEY fork");
		return NULL;
	}

	obj = palloc0_object(TestFileEncryptionObject);
	obj->rel_number = rel;
	return obj;
}

static void
test_file_encryption_object_close(FileEncryptionModuleState *state,
								  void *object_state)
{
	pfree(object_state);
}

/*
 * Symmetric XOR over the full BLCKSZ.  The keystream binds the relation,
 * fork, and block number, so MAIN block N and INIT block N produce
 * different ciphertexts (matching the binding-context semantics of real
 * modules).
 */
static void
test_file_encryption_xor_page(TestFileEncryptionObject *obj, ForkNumber fork,
							  BlockNumber blocknum,
							  const char *src, char *dst)
{
	uint32		seed = obj->rel_number * 2654435761u
		+ (uint32) fork * 16777619u
		+ blocknum;

	for (Size i = 0; i < BLCKSZ; i++)
		dst[i] = src[i] ^ (uint8) (seed + i);
}

static bool
test_file_encryption_encrypt_page(FileEncryptionModuleState *state,
								  void *object_state,
								  ForkNumber fork, BlockNumber blocknum,
								  const char *src, char *dst,
								  char **errmsg)
{
	test_file_encryption_xor_page((TestFileEncryptionObject *) object_state,
								  fork, blocknum, src, dst);
	return true;
}

static bool
test_file_encryption_decrypt_page(FileEncryptionModuleState *state,
								  void *object_state,
								  ForkNumber fork, BlockNumber blocknum,
								  const char *src, char *dst,
								  char **errmsg)
{
	test_file_encryption_xor_page((TestFileEncryptionObject *) object_state,
								  fork, blocknum, src, dst);
	return true;
}
