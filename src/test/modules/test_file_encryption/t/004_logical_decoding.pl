# Copyright (c) 2026, PostgreSQL Global Development Group

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Use the smallest WAL segment size so that a single transaction below can
# easily span multiple segments, exercising the per-segment spill file
# handling on both the write and read paths.
my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init(allows_streaming => 'logical',
			extra => ['--wal-segsize=1',
					  '--file-encryption-library=test_file_encryption']);
$node->append_conf(
	'postgresql.conf', qq(
logical_decoding_work_mem = '64kB'
));
$node->start;

$node->safe_psql('postgres', 'CREATE TABLE spill_test(data text);');
$node->safe_psql('postgres', 'CREATE PUBLICATION pub FOR TABLE spill_test;');
$node->safe_psql('postgres',
	"SELECT pg_create_logical_replication_slot('enc_slot', 'pgoutput');");

# Roughly 5MB of inserts (~5x the 1MB WAL segment size) so the transaction
# spans multiple WAL segments. With logical_decoding_work_mem=64kB this also
# forces spilling, exercising the per-segment spill path on both write and
# read.  Spill files are created and consumed inside a single decoding call,
# so we can't observe them between transactions; the round-trip of all 5000
# rows below is the assertion that the cross-segment path works.
$node->safe_psql('postgres', q[
BEGIN;
INSERT INTO spill_test
SELECT 'encrypt-me:' || repeat('x', 1000) || ':' || g.i
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
   'logical decoding returns all spilled changes with file encryption enabled');

$node->poll_query_until(
	'postgres', q[
SELECT spill_count > 0 AND spill_bytes > 0
FROM pg_stat_replication_slots
WHERE slot_name = 'enc_slot';
]) or die "Timed out while waiting for spill statistics";

ok($node->log_contains(
	qr/test_file_encryption: encrypt_calls=[1-9][0-9]* decrypt_calls=[1-9][0-9]*/,
	0),
	'file encryption callbacks were used for reorderbuffer spill files');

$node->safe_psql('postgres', "SELECT pg_drop_replication_slot('enc_slot');");
$node->stop;

done_testing();
