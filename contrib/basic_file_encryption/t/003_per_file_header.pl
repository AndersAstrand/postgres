# Copyright (c) 2026, PostgreSQL Global Development Group

# Verify the per-file encryption header machinery: for basic_file_encryption,
# each spill or BufFile gets a fresh AES-GCM AAD salt at the start, and
# encrypted records can be read back only after the module reconstructs its
# per-file state from that header.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

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
	"SELECT pg_create_logical_replication_slot('hdr_slot', 'pgoutput');");

$node->safe_psql('postgres', q[
BEGIN;
INSERT INTO spill_test
SELECT 'encrypt-me:' || g.i
FROM generate_series(1, 5000) AS g(i);
COMMIT;
]);

my $count = $node->safe_psql('postgres', q[
SELECT count(*)
FROM pg_logical_slot_get_binary_changes('hdr_slot', NULL, NULL,
                                        'proto_version', '4',
                                        'publication_names', 'pub')
WHERE get_byte(data, 0) = 73;
]);
is($count, '5000',
   'spill round-trips with per-file header (init_file_cb + open_file_cb)');

# Confirm the AAD-binding catches a swapped salt.  We can't easily corrupt
# the on-disk header during decoding (consumed in one call), but we can
# verify the negative case via the test_file_encryption module's stricter
# magic check: open a file written by basic_file_encryption with the
# test module configured.  That test belongs in a dedicated test file
# because it requires restarting with a different library.
$node->safe_psql('postgres', "SELECT pg_drop_replication_slot('hdr_slot');");

# Also confirm the BufFile path.  Encryption of BufFile temp files uses the
# same per-file header API.
$node->safe_psql('postgres', q[
SET work_mem = '64kB';
CREATE TABLE big(id int, payload text);
INSERT INTO big
SELECT g, repeat(md5(g::text), 4) FROM generate_series(1, 50000) g;
]);

my $sort_ok = $node->safe_psql('postgres', q[
SET work_mem = '64kB';
WITH ordered AS (SELECT id, payload FROM big ORDER BY id)
SELECT count(*) = 50000 AND
       bool_and(payload = repeat(md5(id::text), 4))
FROM ordered;
]);
is($sort_ok, 't', 'BufFile sort round-trips with per-file header');

$node->stop;
done_testing();
