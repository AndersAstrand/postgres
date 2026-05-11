# Copyright (c) 2026, PostgreSQL Global Development Group

# Verify that BufFile's decrypt-side validation rejects bogus output from a
# file encryption module.  We use the test module's tamper_mode GUC to force
# the decrypt callback to return wrong-sized plaintext, then expect a sort
# that spills to a BufFile to error out on read-back.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init;
$node->append_conf(
	'postgresql.conf', q(
file_encryption_library = 'test_file_encryption'
hash_mem_multiplier = 1.0
));
$node->start;

# Populate at default work_mem so setup itself doesn't spill — we want to
# control exactly which query exercises the encrypted BufFile.
$node->safe_psql('postgres', q[
CREATE TABLE t (id int, payload text);
INSERT INTO t SELECT g, repeat(md5(g::text), 4)
FROM generate_series(1, 50000) g;
]);

# Switch the test module into decrypt-tampering mode for the next session,
# and squeeze work_mem so the next sort must spill to a BufFile.
$node->safe_psql('postgres', q[
ALTER SYSTEM SET test_file_encryption.tamper_mode = 'decrypt_short';
ALTER SYSTEM SET work_mem = '64kB';
]);
$node->reload;

# ORDER BY with work_mem = 64kB and 50k 128-byte rows must spill to a
# BufFile, then read it back during the merge.  With tamper_mode active
# the read-back path must surface the size-mismatch error.
my ($ret, $stdout, $stderr) = $node->psql('postgres', q[
SELECT count(*) FROM (SELECT * FROM t ORDER BY id) s;
]);
isnt($ret, 0, 'tampered decrypt fails the BufFile read-back');
like($stderr,
	 qr/decrypted plaintext size \d+ does not match header \d+/,
	 'BufFile size-mismatch error fires');

$node->stop;
done_testing();
