# Copyright (c) 2026, PostgreSQL Global Development Group

# Exercise encrypted BufFile via the sort and hash-join paths.  We force
# work_mem low enough that a large SELECT must spill to temporary BufFiles,
# then verify that the round-trip through AES-256-GCM faithfully reproduces
# the original rows.

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
$node->init(extra => ['--file-encryption-library=basic_file_encryption',
					  "--file-encryption-config=$key"]);
$node->append_conf(
	'postgresql.conf', qq(
work_mem = '64kB'
hash_mem_multiplier = 1.0
));
$node->start;

# Create a table whose rows are self-verifying: payload is a deterministic
# function of id.  Any byte-level corruption introduced by encryption will
# fail the equality check, regardless of which work_mem path was used.
$node->safe_psql('postgres', q[
CREATE TABLE t (id int, payload text);
INSERT INTO t
SELECT g, repeat(md5(g::text), 4)
FROM generate_series(1, 50000) g;
]);

# 1. ORDER BY that spills (work_mem = 64kB, payload is 128 bytes per row).
my $sort_ok = $node->safe_psql('postgres', q[
WITH ordered AS (SELECT id, payload FROM t ORDER BY id)
SELECT count(*) = 50000 AND
       bool_and(payload = repeat(md5(id::text), 4)) AND
       (array_agg(id))[1:5] = ARRAY[1, 2, 3, 4, 5]
FROM (SELECT id, payload FROM ordered) s;
]);
is($sort_ok, 't', 'sort spilled and decrypted bytes match originals');

# 2. Hash join with low work_mem forces batching.  Each batch lives in its
#    own BufFile, so this exercises multiple encrypted BufFiles in one
#    query.
my $hashjoin_ok = $node->safe_psql('postgres', q[
SET enable_mergejoin = off;
SET enable_nestloop = off;
SELECT count(*) = 50000 AND
       bool_and(a.payload = b.payload AND a.payload = repeat(md5(a.id::text), 4))
FROM t a JOIN t b USING (id);
]);
is($hashjoin_ok, 't', 'hash join with batching round-tripped through encrypted BufFiles');

# 3. Scroll cursor exercises tuplestore + backwards seeks across spilled
#    blocks.  We jump well past the work_mem threshold, then back, and
#    verify the same row reappears with intact bytes.
my $expected_payload =
  $node->safe_psql('postgres', "SELECT repeat(md5('25000'), 4);");
my $cursor_row = $node->safe_psql('postgres', q[
BEGIN;
DECLARE c SCROLL CURSOR FOR SELECT id, payload FROM t ORDER BY id;
MOVE ABSOLUTE 30000 IN c;
FETCH ABSOLUTE 25000 FROM c;
COMMIT;
]);
is($cursor_row, "25000|$expected_payload",
   'scroll cursor backwards across encrypted BufFile returns matching row')
  or note("got: $cursor_row");

$node->stop;
done_testing();
