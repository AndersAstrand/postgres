# Copyright (c) 2026, PostgreSQL Global Development Group

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
$node->append_conf(
	'postgresql.conf', qq(
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

my $sort_ok = $node->safe_psql('postgres', q[
WITH ordered AS (SELECT id, payload FROM t ORDER BY id)
SELECT count(*) = 50000 AND
       bool_and(payload = repeat(md5(id::text), 4)) AND
       (array_agg(id))[1:5] = ARRAY[1, 2, 3, 4, 5]
FROM (SELECT id, payload FROM ordered) s;
]);
is($sort_ok, 't', 'sort spilled and round-tripped through SM4 module');

$node->stop;
done_testing();
