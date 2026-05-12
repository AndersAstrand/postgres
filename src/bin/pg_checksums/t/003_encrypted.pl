# Copyright (c) 2026, PostgreSQL Global Development Group

# Verify pg_checksums against an encrypted cluster: configure
# basic_file_encryption at initdb time, populate a few relations, stop the
# cluster, then run pg_checksums --check both with and without the
# encryption config supplied.  Also exercise --enable on a no-checksums
# encrypted cluster (decrypt -> set pd_checksum -> re-encrypt -> write
# back) and confirm the result verifies.

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

#
# --- Phase 1: --check on a cluster that initdb'd WITH data-checksums on.
#
my $node = PostgreSQL::Test::Cluster->new('encrypted');
$node->init(
	extra => [
		'--file-encryption-library=basic_file_encryption',
		"--file-encryption-config=$key"
	]);
$node->append_conf('postgresql.conf', qq[
file_encryption_config = '$key'
]);
$node->start;

# Create heap + btree with a deterministic payload; checkpoint forces
# pages to disk via the encrypted mdwritev path.
$node->safe_psql('postgres', q[
CREATE TABLE t (id int PRIMARY KEY, payload text);
INSERT INTO t SELECT g, repeat(md5(g::text), 4) FROM generate_series(1, 2000) g;
CHECKPOINT;
]);

$node->stop;

my $datadir = $node->data_dir;

# Missing config: pg_checksums --check must refuse with a useful error.
$node->command_checks_all(
	[ 'pg_checksums', '--check', '-D', $datadir ],
	1,
	[],
	[qr/cluster was initialized with file encryption but no configuration was supplied/],
	'pg_checksums --check fails without an encryption config');

# With the config supplied, --check succeeds across all forks.
$node->command_checks_all(
	[ 'pg_checksums', '--check',
	  '--file-encryption-config', $key,
	  '-D', $datadir ],
	0,
	[qr/Bad checksums:\s*0/],
	[],
	'pg_checksums --check passes for the encrypted cluster');

# Same, but via the PGFILEENCRYPTIONCONFIG env var fallback.
local $ENV{PGFILEENCRYPTIONCONFIG} = $key;
$node->command_checks_all(
	[ 'pg_checksums', '--check', '-D', $datadir ],
	0,
	[qr/Bad checksums:\s*0/],
	[],
	'pg_checksums --check reads config from PGFILEENCRYPTIONCONFIG');
delete $ENV{PGFILEENCRYPTIONCONFIG};

#
# --- Phase 2: --enable on a no-checksums encrypted cluster.
#
my $key2 = random_key();
my $node2 = PostgreSQL::Test::Cluster->new('encrypted_nocsums');
$node2->init(
	extra => [
		'--no-data-checksums',
		'--file-encryption-library=basic_file_encryption',
		"--file-encryption-config=$key2"
	]);
$node2->append_conf('postgresql.conf', qq[
file_encryption_config = '$key2'
]);
$node2->start;
$node2->safe_psql('postgres', q[
CREATE TABLE t (id int PRIMARY KEY, payload text);
INSERT INTO t SELECT g, repeat(md5(g::text), 4) FROM generate_series(1, 2000) g;
CHECKPOINT;
]);
$node2->stop;

my $datadir2 = $node2->data_dir;

$node2->command_checks_all(
	[ 'pg_checksums', '--enable',
	  '--file-encryption-config', $key2,
	  '-D', $datadir2 ],
	0,
	[qr/Checksums enabled in cluster/],
	[],
	'pg_checksums --enable succeeds on encrypted cluster');

# Restart the cluster and round-trip a value to confirm the re-encrypted
# blocks decrypt correctly under the original DEK.
$node2->start;
my $count = $node2->safe_psql('postgres', 'SELECT count(*) FROM t;');
is($count, '2000', 'all rows readable after --enable round-trip');
my $sample = $node2->safe_psql('postgres', "SELECT payload FROM t WHERE id = 1234;");
my $expected = $node2->safe_psql('postgres', "SELECT repeat(md5('1234'), 4);");
is($sample, $expected, 'payload bytes intact after --enable round-trip');
$node2->stop;

# Final --check confirms the rewritten checksums verify.
$node2->command_checks_all(
	[ 'pg_checksums', '--check',
	  '--file-encryption-config', $key2,
	  '-D', $datadir2 ],
	0,
	[qr/Bad checksums:\s*0/],
	[],
	'pg_checksums --check passes after --enable');

done_testing();
