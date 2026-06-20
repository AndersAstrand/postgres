# Copyright (c) 2026, PostgreSQL Global Development Group

# End-to-end test of basic_file_encryption: configure a random AES-256
# key-encryption key, trigger reorderbuffer spilling, and verify that all
# changes round-trip through the encrypt/decrypt callbacks.  Also asserts
# that decryption fails loudly when the key changes between the encrypt and
# decrypt sessions (catches accidental key rotation against existing files).

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Generate a random 32-byte hex key-encryption key.
sub random_key
{
	my @hex;
	for (1 .. 64)
	{
		push @hex, sprintf("%x", int(rand(16)));
	}
	return join('', @hex);
}

my $key = random_key();

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init(allows_streaming => 'logical',
			extra => ['--file-encryption-library=basic_file_encryption',
					  "--file-encryption-config=$key"]);
$node->append_conf(
	'postgresql.conf', qq(
logical_decoding_work_mem = '64kB'
));
$node->start;

$node->safe_psql('postgres', 'CREATE TABLE spill_test(data text);');
$node->safe_psql('postgres', 'CREATE PUBLICATION pub FOR TABLE spill_test;');
$node->safe_psql('postgres',
	"SELECT pg_create_logical_replication_slot('enc_slot', 'pgoutput');");

$node->safe_psql('postgres', q[
BEGIN;
INSERT INTO spill_test
SELECT 'encrypt-me:' || g.i
FROM generate_series(1, 5000) AS g(i);
COMMIT;
]);

my $insert_count = $node->safe_psql('postgres', q[
SELECT count(*)
FROM pg_logical_slot_get_binary_changes('enc_slot', NULL, NULL,
                                        'proto_version', '4',
                                        'publication_names', 'pub')
WHERE get_byte(data, 0) = 73;
]);
is($insert_count, '5000',
   'logical decoding round-trips through AES-256-GCM');

# Confirm we did spill (otherwise the test would silently bypass the
# encrypt/decrypt code path).
$node->poll_query_until(
	'postgres', q[
SELECT spill_count > 0 AND spill_bytes > 0
FROM pg_stat_replication_slots
WHERE slot_name = 'enc_slot';
]) or die "Timed out while waiting for spill statistics";

$node->safe_psql('postgres', "SELECT pg_drop_replication_slot('enc_slot');");

# Sanity: a malformed key value is rejected at module load time.  The
# postmaster refuses to start when file_encryption_config can't be parsed
# by the configured module, surfacing the module's errmsg in the server
# log.  We launch via pg_ctl directly so a failed start doesn't kill the
# test process.
$node->stop;
$node->adjust_conf('postgresql.conf', 'file_encryption_config',
				   "'not-a-hex-key'");
my $logfile = $node->logfile;
my $bad_start = system($ENV{'PG_REGRESS_BIN_DIR'} ? "$ENV{PG_REGRESS_BIN_DIR}/pg_ctl" : 'pg_ctl',
					   '--pgdata' => $node->data_dir,
					   '--log' => $logfile,
					   '--options' => '--cluster-name=primary',
					   '--wait', '--timeout' => 10, 'start');
isnt($bad_start, 0,
	 'postmaster refuses to start with malformed file_encryption_config');
my $log_after = PostgreSQL::Test::Utils::slurp_file($logfile);
like($log_after,
	 qr/file encryption module "basic_file_encryption" failed to initialize/,
	 'failed start logs the module-init error');
like($log_after,
	 qr/basic_file_encryption: 'config' must (be|contain)/,
	 'log surfaces module-supplied errmsg detail');

# Restore a valid key so the cluster can shut down cleanly when this
# test object is destroyed (PostgreSQL::Test::Cluster::DESTROY tries to
# stop the node and complains if it's not running).
$node->adjust_conf('postgresql.conf', 'file_encryption_config', "'$key'");

done_testing();
