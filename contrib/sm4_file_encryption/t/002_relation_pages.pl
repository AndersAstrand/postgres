# Copyright (c) 2026, PostgreSQL Global Development Group

# Page-encryption test for sm4_file_encryption: per-relation DEK held in
# the relation's KEY fork, page trailer carries IV + HMAC tag + format.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

sub openssl_has_algorithm
{
	my ($option, $name) = @_;
	my $output = `openssl list -$option 2>&1`;
	return $output =~ /\b\Q$name\E\b/i;
}

plan skip_all => 'OpenSSL does not expose SM4-CTR'
  unless openssl_has_algorithm('cipher-algorithms', 'SM4-CTR');
plan skip_all => 'OpenSSL does not expose SM3'
  unless openssl_has_algorithm('digest-algorithms', 'SM3');

sub random_key
{
	my @hex;
	for (1 .. 32)
	{
		push @hex, sprintf("%x", int(rand(16)));
	}
	return join('', @hex);
}

my $key = random_key();

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init(extra => ['--file-encryption-library=sm4_file_encryption',
					  "--file-encryption-config=key=$key"]);
$node->start;

$node->safe_psql('postgres', q[
CREATE TABLE t (id int PRIMARY KEY, payload text);
INSERT INTO t SELECT g, repeat(md5(g::text), 4)
FROM generate_series(1, 5000) g;
CHECKPOINT;
]);

my $count = $node->safe_psql('postgres', 'SELECT count(*) FROM t;');
is($count, '5000', 'seqscan round-trip through encrypted heap pages');

$node->restart;
my $restart_count = $node->safe_psql('postgres', 'SELECT count(*) FROM t;');
is($restart_count, '5000', 'round-trip across restart');

my $restart_sample = $node->safe_psql('postgres',
	"SELECT payload FROM t WHERE id = 1234;");
my $expected_sample = $node->safe_psql('postgres',
	"SELECT repeat(md5('1234'), 4);");
is($restart_sample, $expected_sample, 'tuple bytes match across restart');

# On-disk: heap fork shouldn't contain plaintext payload.
my $datadir = $node->data_dir;
my $reloid = $node->safe_psql('postgres',
	"SELECT relfilenode FROM pg_class WHERE relname = 't';");
my $dboid = $node->safe_psql('postgres',
	"SELECT oid FROM pg_database WHERE datname = 'postgres';");
my $heap_path = "$datadir/base/$dboid/$reloid";

my $marker = $node->safe_psql('postgres',
	"SELECT substr(repeat(md5('1'), 4), 1, 32);");

open my $fh, '<:raw', $heap_path or die "open $heap_path: $!";
local $/ = undef;
my $content = <$fh>;
close $fh;
ok(index($content, $marker) < 0,
   'heap fork on disk does not contain plaintext payload');

done_testing();
