# Copyright (c) 2026, PostgreSQL Global Development Group

# Verify that reorderbuffer's decrypt-side validation rejects bogus output
# from a file encryption module.  We use the test module's tamper_mode GUC
# to force the decrypt callback to return wrong-sized plaintext, then expect
# pg_logical_slot_get_binary_changes to error out.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init(allows_streaming => 'logical');
$node->append_conf(
	'postgresql.conf', qq(
file_encryption_library = 'test_file_encryption'
logical_decoding_work_mem = '64kB'
));
$node->start;

$node->safe_psql('postgres', 'CREATE TABLE spill_test(data text);');
$node->safe_psql('postgres', 'CREATE PUBLICATION pub FOR TABLE spill_test;');

# Helper: spill, attempt to decode, expect a specific error message.
sub check_tamper
{
	my ($mode, $slot, $expected_error, $label) = @_;

	$node->safe_psql('postgres',
		"SELECT pg_create_logical_replication_slot('$slot', 'pgoutput');");

	# Spill some changes.  The slot was created above, so this transaction
	# is captured by it and will need to be decoded out of spill files.
	$node->safe_psql('postgres', q[
BEGIN;
INSERT INTO spill_test
SELECT 'encrypt-me:' || g.i
FROM generate_series(1, 5000) AS g(i);
COMMIT;
]);

	# Switch the test module into the requested tamper mode for the
	# decoding session that's about to spill+restore.
	$node->safe_psql('postgres',
		"ALTER SYSTEM SET test_file_encryption.tamper_mode = '$mode';");
	$node->reload;

	my ($ret, $stdout, $stderr) = $node->psql(
		'postgres', qq[
SELECT count(*)
FROM pg_logical_slot_get_binary_changes('$slot', NULL, NULL,
                                        'proto_version', '4',
                                        'publication_names', 'pub');
]);
	isnt($ret, 0, "tamper_mode=$mode causes decode failure ($label)");
	like($stderr, $expected_error,
		 "tamper_mode=$mode surfaces expected error ($label)");

	# Restore default and drop the slot.
	$node->safe_psql('postgres',
		"ALTER SYSTEM SET test_file_encryption.tamper_mode = 'none';");
	$node->reload;
	$node->safe_psql('postgres', "SELECT pg_drop_replication_slot('$slot');");
}

check_tamper('decrypt_short', 'tamper_short',
	qr/file encryption module returned \d+ bytes instead of \d+ bytes/,
	'short plaintext');

$node->stop;

done_testing();
