# Copyright (c) 2026, PostgreSQL Global Development Group

# Smoke-test BufFile encryption end-to-end with the test_file_encryption
# module: load the module, force a sort to spill, and check that the
# self-verifying payload column round-trips.  Also verify the encrypt_cb
# and decrypt_cb callbacks fire by inspecting the summary line the module
# emits at backend exit.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init(extra => ['--file-encryption-library=test_file_encryption']);
$node->append_conf(
	'postgresql.conf', q(
work_mem = '64kB'
hash_mem_multiplier = 1.0
));
$node->start;

$node->safe_psql('postgres', q[
CREATE TABLE t (id int, payload text);
INSERT INTO t
SELECT g, repeat(md5(g::text), 4)
FROM generate_series(1, 50000) g;
]);

# ORDER BY with work_mem=64kB and 50k 128-byte payload rows must spill
# to disk; bool_and over the deterministic payload catches any byte-level
# corruption introduced by the encrypt/decrypt round-trip.
my $sort_ok = $node->safe_psql('postgres', q[
WITH ordered AS (SELECT id, payload FROM t ORDER BY id)
SELECT count(*) = 50000 AND
       bool_and(payload = repeat(md5(id::text), 4)) AND
       (array_agg(id))[1:5] = ARRAY[1, 2, 3, 4, 5]
FROM (SELECT id, payload FROM ordered) s;
]);
is($sort_ok, 't', 'sort spilled and round-tripped through encrypted BufFile');

# Disconnect so the backend's before_shmem_exit callback flushes the
# module's summary, then poll the server log for proof that the
# encrypt/decrypt callbacks fired.
$node->stop;

ok($node->log_contains(
	qr/test_file_encryption: encrypt_calls=[1-9][0-9]* decrypt_calls=[1-9][0-9]*/
   ),
	'encrypt/decrypt callbacks were exercised');

done_testing();
