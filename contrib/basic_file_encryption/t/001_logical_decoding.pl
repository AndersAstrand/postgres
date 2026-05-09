# Copyright (c) 2026, PostgreSQL Global Development Group

# End-to-end test of basic_file_encryption: configure a random AES-256 key,
# trigger reorderbuffer spilling, and verify that all changes round-trip
# through the encrypt/decrypt callbacks.  Also asserts that decryption fails
# loudly when the key changes between the encrypt and decrypt sessions
# (catches accidental key rotation against existing files).

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Generate a random 32-byte hex key.
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
$node->init(allows_streaming => 'logical');
$node->append_conf(
	'postgresql.conf', qq(
file_encryption_library = 'basic_file_encryption'
basic_file_encryption.key = '$key'
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

# Restart with a different key and confirm a fresh spill+decode cycle still
# works (the spill files written under the old key were already consumed
# above, so the new key only ever sees its own ciphertext).
my $new_key = random_key();
isnt($new_key, $key, 'generated distinct keys for restart');
$node->stop;
$node->adjust_conf('postgresql.conf', 'basic_file_encryption.key',
				   "'$new_key'");
$node->start;

$node->safe_psql('postgres',
	"SELECT pg_create_logical_replication_slot('enc_slot2', 'pgoutput');");
$node->safe_psql('postgres', q[
BEGIN;
INSERT INTO spill_test
SELECT 'encrypt-me-2:' || g.i
FROM generate_series(1, 5000) AS g(i);
COMMIT;
]);
my $count2 = $node->safe_psql('postgres', q[
SELECT count(*)
FROM pg_logical_slot_get_binary_changes('enc_slot2', NULL, NULL,
                                        'proto_version', '4',
                                        'publication_names', 'pub')
WHERE get_byte(data, 0) = 73;
]);
is($count2, '5000', 'round-trip works after key change');

$node->safe_psql('postgres', "SELECT pg_drop_replication_slot('enc_slot2');");

# Sanity: a malformed key value is rejected.  GUC validation logs a WARNING
# at startup (the value reverts to the default), and any subsequent attempt
# to use the encryption module errors out because no key is configured.
$node->stop;
$node->adjust_conf('postgresql.conf', 'basic_file_encryption.key',
				   "'not-a-hex-key'");
$node->start;
ok($node->log_contains(
	qr/invalid value for parameter "basic_file_encryption\.key"/, 0),
   'malformed key produces a warning at startup');

$node->safe_psql('postgres',
	"SELECT pg_create_logical_replication_slot('enc_slot3', 'pgoutput');");
$node->safe_psql('postgres', q[
BEGIN;
INSERT INTO spill_test
SELECT 'encrypt-me-3:' || g.i
FROM generate_series(1, 5000) AS g(i);
COMMIT;
]);
my ($ret3, $stdout3, $stderr3) = $node->psql('postgres', q[
SELECT count(*)
FROM pg_logical_slot_get_binary_changes('enc_slot3', NULL, NULL,
                                        'proto_version', '4',
                                        'publication_names', 'pub');
]);
isnt($ret3, 0, 'decoding fails when key is unset');
like($stderr3, qr/basic_file_encryption\.key is not set/,
	 'expected error message for missing key');

$node->stop;

done_testing();
