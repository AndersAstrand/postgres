
# Copyright (c) 2021-2026, PostgreSQL Global Development Group

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

program_help_ok('dropuser');
program_version_ok('dropuser');
program_options_handling_ok('dropuser');

my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->start;

$node->safe_psql('postgres', 'CREATE ROLE regress_foobar1');
$node->issues_sql_like(
	[ 'dropuser', 'regress_foobar1' ],
	qr/statement: DROP ROLE regress_foobar1/,
	'SQL DROP ROLE run');

$node->command_fails_like(
	[ 'dropuser', 'regress_nonexistent' ],
	qr/role "regress_nonexistent" does not exist/,
	'fails with nonexistent user');

# These tests needs to run last as we have to break the cluster somewhat to run them.

$node->safe_psql('postgres', 'CREATE ROLE regress_foobar2');
$node->safe_psql('postgres', 'CREATE ROLE regress_foobar3');
$node->safe_psql('postgres', 'CREATE ROLE regress_foobar4');

$node->safe_psql('postgres', 'CREATE DATABASE maintenance');
$node->safe_psql('maintenance', 'DROP DATABASE postgres');
$node->safe_psql('maintenance',
	"UPDATE pg_database SET datistemplate=false WHERE datname='template1'");
$node->safe_psql('maintenance', 'DROP DATABASE template1');

$node->command_fails([ 'dropuser', 'regress_foobar2' ],
	'fails when default databases do not exist');

$node->command_ok(
	[
		'dropuser',
		'--maintenance-db' => 'maintenance',
		'regress_foobar3',
	],
	'succeeds when maintenance database name is specified');

$node->command_ok(
	[
		'dropuser',
		'--maintenance-db' => 'postgresql:///maintenance',
		'regress_foobar4',
	],
	'succeeds when connection string is specified');

done_testing();
