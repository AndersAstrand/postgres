# Copyright (c) 2026, PostgreSQL Global Development Group

# Smoke test for basic_file_encryption: configure the module at initdb
# time, start the cluster, and verify that bootstrap + relation creation
# (which invokes the page-encryption callbacks for every catalog write)
# completes cleanly.  Downstream commits add tests that exercise the
# BufFile, reorderbuffer, and relation-page paths against real workloads.

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
$node->init(
	extra => [
		'--file-encryption-library=basic_file_encryption',
		"--file-encryption-config=$key"
	]);
$node->append_conf('postgresql.conf', qq[
file_encryption_config = '$key'
]);
$node->start;

# Cluster started, so initdb's bootstrap + post-bootstrap backends all
# successfully encrypted their writes and decrypted them back on the
# next read.  As a tiny additional sanity check, create a table and
# round-trip a value through it -- that exercises the page-encryption
# callbacks against fresh on-disk content.
my $value = $node->safe_psql('postgres', q[
CREATE TABLE smoke (id int, payload text);
INSERT INTO smoke VALUES (1, 'hello, encrypted world');
CHECKPOINT;
SELECT payload FROM smoke WHERE id = 1;
]);
is($value, 'hello, encrypted world',
	'plaintext round-trips through page-encrypted heap');

$node->stop;
done_testing();
