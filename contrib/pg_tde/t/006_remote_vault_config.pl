#!/usr/bin/perl

use strict;
use warnings;
use Env;
use File::Basename;
use HTTP::Request;
use JSON;
use LWP::UserAgent;
use Test::More;
use lib 't';
use pgtde;

our $token = create_vault_token();

{

	package MyWebServer;

	use HTTP::Server::Simple::CGI;
	use base qw(HTTP::Server::Simple::CGI);

	my %dispatch = (
		'/token' => \&resp_token,
		'/url' => \&resp_url,);

	sub handle_request
	{
		my $self = shift;
		my $cgi = shift;

		my $path = $cgi->path_info();
		my $handler = $dispatch{$path};

		if (ref($handler) eq "CODE")
		{
			print "HTTP/1.0 200 OK\r\n";
			$handler->($cgi);

		}
		else
		{
			print "HTTP/1.0 404 Not found\r\n";
			print $cgi->header,
			  $cgi->start_html('Not found'),
			  $cgi->h1('Not found'),
			  $cgi->end_html;
		}
	}

	sub resp_token
	{
		my $cgi = shift;
		print $cgi->header, "$token\r\n";
	}

	sub resp_url
	{
		my $cgi = shift;
		print $cgi->header, "http://127.0.0.1:8200\r\n";
	}

}

my $pid = MyWebServer->new(8889)->background();

PGTDE::setup_files_dir(basename($0));

my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_tde'");
$node->start;

PGTDE::psql($node, 'postgres', 'CREATE EXTENSION IF NOT EXISTS pg_tde;');

PGTDE::psql($node, 'postgres',
	"SELECT pg_tde_add_database_key_provider_vault_v2('vault-provider', json_object('type' VALUE 'remote', 'url' VALUE 'http://localhost:8889/token'), json_object('type' VALUE 'remote', 'url' VALUE 'http://localhost:8889/url'), to_json('secret'::text), NULL);"
);
PGTDE::psql($node, 'postgres',
	"SELECT pg_tde_set_key_using_database_key_provider('test-db-key', 'vault-provider');"
);

PGTDE::psql($node, 'postgres',
	'CREATE TABLE test_enc2 (id SERIAL, k INTEGER, PRIMARY KEY (id)) USING tde_heap;'
);

PGTDE::psql($node, 'postgres', 'INSERT INTO test_enc2 (k) VALUES (5), (6);');

PGTDE::psql($node, 'postgres', 'SELECT * FROM test_enc2 ORDER BY id;');

PGTDE::append_to_result_file("-- server restart");
$node->restart;

PGTDE::psql($node, 'postgres', 'SELECT * FROM test_enc2 ORDER BY id;');

PGTDE::psql($node, 'postgres', 'DROP TABLE test_enc2;');

# Token can be rotated
PGTDE::psql($node, 'postgres',
	q{SELECT pg_tde_add_database_key_provider_vault_v2('vault-provider-2', '{"type": "remote", "url": "http://localhost:8889/token"}'::json, '"http://127.0.0.1:8200"'::json, '"secret"'::json, NULL)}
);
PGTDE::psql($node, 'postgres',
	"SELECT pg_tde_set_key_using_database_key_provider('db-key', 'vault-provider-2');"
);
my $new_token = create_vault_token();
revoke_vault_token($token);
$token = $new_token;
my $pid2 = MyWebServer->new(8899)->background();
PGTDE::psql($node, 'postgres',
	q{SELECT pg_tde_change_database_key_provider_vault_v2('vault-provider-2', '{"type": "remote", "url": "http://localhost:8899/token"}'::json, '"http://127.0.0.1:8200"'::json, '"secret"'::json, NULL)}
);
$node->restart; # Restart to ensure principal key is not cached.
PGTDE::psql($node, 'postgres', 'SELECT pg_tde_verify_key()');

PGTDE::psql($node, 'postgres', 'DROP EXTENSION pg_tde;');

$node->stop;

kill('TERM', $pid);
kill('TERM', $pid2);

# Compare the expected and out file
my $compare = PGTDE->compare_results();

is($compare, 0,
	"Compare Files: $PGTDE::expected_filename_with_path and $PGTDE::out_filename_with_path files."
);

done_testing();

sub create_vault_token
{
	my $request = HTTP::Request->new(
		'POST',
		'http://127.0.0.1:8200/v1/auth/token/create',
		[
			'X-Vault-Token' => $ENV{'ROOT_TOKEN'},
			'Content-Type' => 'application/json',
		],
		encode_json({'policies' => ['root']}),
	);

	my $result = LWP::UserAgent->new->request($request);

	decode_json($result->decoded_content)->{'auth'}->{'client_token'};
};

sub revoke_vault_token
{
	my ($revoke_token) = @_;

	my $request = HTTP::Request->new(
		'PUT',
		'http://127.0.0.1:8200/v1/auth/token/revoke-self',
		[
			'X-Vault-Token' => $revoke_token,
			'Content-Type' => 'application/json',
		],
	);

	LWP::UserAgent->new->request($request);
}
