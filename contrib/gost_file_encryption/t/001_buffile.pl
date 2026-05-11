# Copyright (c) 2026, PostgreSQL Global Development Group

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $cipher = $ENV{PG_TEST_GOST_CIPHER} || 'kuznyechik-ctr';
my $digest = $ENV{PG_TEST_GOST_DIGEST} || 'md_gost12_256';
my $provider = $ENV{PG_TEST_GOST_PROVIDER} || 'gostprov';

sub openssl_has_algorithm
{
	my ($option, $name) = @_;
	my $provider_opt = $provider ne '' ? " -provider '$provider'" : '';
	my $output = `openssl list -$option$provider_opt 2>&1`;
	return $output =~ /\b\Q$name\E\b/i;
}

plan skip_all => "OpenSSL does not expose $cipher"
  unless openssl_has_algorithm('cipher-algorithms', $cipher);
plan skip_all => "OpenSSL does not expose $digest"
  unless openssl_has_algorithm('digest-algorithms', $digest);

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
$node->init;
$node->append_conf(
	'postgresql.conf', qq(
file_encryption_library = 'gost_file_encryption'
gost_file_encryption.key = '$key'
gost_file_encryption.cipher = '$cipher'
gost_file_encryption.digest = '$digest'
work_mem = '64kB'
hash_mem_multiplier = 1.0
));
$node->append_conf('postgresql.conf',
	"gost_file_encryption.provider = '$provider'\n")
  if $provider ne '';
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
is($sort_ok, 't', 'sort spilled and round-tripped through GOST module');

$node->stop;
done_testing();
