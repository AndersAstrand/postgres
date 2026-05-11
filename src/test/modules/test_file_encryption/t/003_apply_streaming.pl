# Copyright (c) 2026, PostgreSQL Global Development Group

# Exercise logical replication apply streaming while the subscriber encrypts
# streamed-changes BufFiles.  streaming=on serializes streamed changes to a
# BufFile and reopens it for later stream segments; the rollback-to-savepoint
# case also truncates that file at a logical byte offset.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node_publisher = PostgreSQL::Test::Cluster->new('publisher');
$node_publisher->init(allows_streaming => 'logical');
$node_publisher->append_conf(
	'postgresql.conf', qq(
logical_decoding_work_mem = '64kB'
debug_logical_replication_streaming = immediate
));
$node_publisher->start;

my $node_subscriber = PostgreSQL::Test::Cluster->new('subscriber');
$node_subscriber->init;
$node_subscriber->append_conf(
	'postgresql.conf', qq(
file_encryption_library = 'test_file_encryption'
test_file_encryption.log_summary = on
log_min_messages = debug1
));
$node_subscriber->start;

$node_publisher->safe_psql('postgres',
	'CREATE TABLE stream_test (id int primary key, payload text);');
$node_subscriber->safe_psql('postgres',
	'CREATE TABLE stream_test (id int primary key, payload text);');

my $publisher_connstr = $node_publisher->connstr . ' dbname=postgres';
my $appname = 'tap_sub';

$node_publisher->safe_psql('postgres',
	'CREATE PUBLICATION tap_pub FOR TABLE stream_test;');
$node_subscriber->safe_psql(
	'postgres',
	"CREATE SUBSCRIPTION tap_sub CONNECTION '$publisher_connstr application_name=$appname' "
	  . "PUBLICATION tap_pub WITH (streaming = on, copy_data = false)"
);

$node_publisher->wait_for_catchup($appname);

my $log_offset = -s $node_subscriber->logfile;

$node_publisher->safe_psql(
	'postgres', q[
BEGIN;
INSERT INTO stream_test
SELECT i, repeat(md5(i::text), 7)
FROM generate_series(1, 20) AS s(i);
SAVEPOINT s1;
INSERT INTO stream_test
SELECT i, repeat(md5(i::text), 7)
FROM generate_series(21, 30) AS s(i);
ROLLBACK TO s1;
INSERT INTO stream_test
SELECT i, repeat(md5(i::text), 7)
FROM generate_series(31, 40) AS s(i);
COMMIT;
]);

$node_publisher->wait_for_catchup($appname);

my $result = $node_subscriber->safe_psql('postgres', q[
SELECT count(*),
       min(id),
       max(id),
       count(*) FILTER (WHERE id BETWEEN 21 AND 30),
       bool_and(payload = repeat(md5(id::text), 7))
FROM stream_test;
]);
is($result, '30|1|40|0|t',
   'streamed transaction with subtransaction abort applied correctly');

ok($node_subscriber->log_contains(
		qr/opening file "\d+-\d+\.changes" for streamed changes.*opening file "\d+-\d+\.changes" for streamed changes/s,
		$log_offset),
	'apply worker reopened encrypted streamed-changes file');

ok($node_subscriber->log_contains(
		qr/finished processing the STREAM ABORT command/s,
		$log_offset),
	'apply worker processed streamed subtransaction abort');

$node_subscriber->stop;
$node_publisher->stop;

ok($node_subscriber->log_contains(
		qr/test_file_encryption: encrypt_calls=[1-9][0-9]* decrypt_calls=[1-9][0-9]*/,
		0),
	'file encryption callbacks were used by apply streaming');

done_testing();
