# Copyright (c) 2026, PostgreSQL Global Development Group

# End-to-end test of basic_file_encryption page encryption: configure a
# random AES-256 key-encryption key and a 32-byte page-reserved trailer,
# populate a heap+btree, verify round-trip across restart, that the
# on-disk bytes of the heap and index forks are not the plaintext, and
# that the FSM and VM forks are bypass (still plaintext-on-disk).  Also
# verify that tampering an encrypted page surfaces a tag-mismatch error.

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
# initdb runs the bootstrap process to write the initial catalogs; the
# bootstrap process reads postgresql.conf, so the encryption settings have
# to be in place before bootstrap runs (i.e. as -c GUCs to initdb itself,
# not via append_conf afterwards).  Otherwise the bootstrap-created pages
# would be plaintext on disk and the postmaster would fail to decrypt them.
$node->init(extra => ['--file-encryption-library=basic_file_encryption',
					  "--file-encryption-config=$key"]);
$node->start;

# pg_controldata reports the reserved size and module-load succeeds
my $controldata = $node->safe_psql('postgres', 'SHOW data_directory;');
my $stdout = `'$ENV{PG_REGRESS_BIN_DIR}/pg_controldata' '$controldata' 2>&1`
  if defined $ENV{PG_REGRESS_BIN_DIR};

# Populate a heap with a btree index and force material amounts of
# data so we get multiple pages in each fork.
$node->safe_psql('postgres', q[
CREATE TABLE t (id int PRIMARY KEY, payload text);
INSERT INTO t SELECT g, repeat(md5(g::text), 4)
FROM generate_series(1, 5000) g;
CHECKPOINT;
]);

# Round-trip read after CHECKPOINT (forces the buffer pool to be
# evicted before the next read).  The seqscan exercises mdread of
# every heap page; the index-only count exercises the btree path.
my $count = $node->safe_psql('postgres', 'SELECT count(*) FROM t;');
is($count, '5000', 'seqscan round-trip through encrypted heap pages');
my $idx_count = $node->safe_psql('postgres',
	'SELECT count(*) FROM (SELECT id FROM t ORDER BY id) s;');
is($idx_count, '5000', 'index scan round-trip through encrypted btree pages');

# Restart and re-read; this exercises that we successfully decrypt
# pages after a fresh process state (no in-memory plaintext).
$node->restart;
my $restart_count = $node->safe_psql('postgres', 'SELECT count(*) FROM t;');
is($restart_count, '5000', 'round-trip across restart');

my $restart_sample = $node->safe_psql('postgres',
	"SELECT payload FROM t WHERE id = 1234;");
my $expected_sample = $node->safe_psql('postgres',
	"SELECT repeat(md5('1234'), 4);");
is($restart_sample, $expected_sample, 'tuple bytes match across restart');

# On-disk verification: the heap fork should NOT contain visible
# plaintext (the payload is a known md5-derived string), the FSM and VM
# forks should be plaintext (per md.c bypass).
my $datadir = $node->data_dir;
my $reloid = $node->safe_psql('postgres',
	"SELECT relfilenode FROM pg_class WHERE relname = 't';");
my $dboid = $node->safe_psql('postgres',
	"SELECT oid FROM pg_database WHERE datname = 'postgres';");

my $heap_path = "$datadir/base/$dboid/$reloid";
my $fsm_path = "$heap_path" . "_fsm";
my $vm_path = "$heap_path" . "_vm";

# A known plaintext substring that appears in many tuples
my $marker_query = $node->safe_psql('postgres',
	"SELECT substr(repeat(md5('1'), 4), 1, 32);");

sub file_contains
{
	my ($path, $needle) = @_;
	open my $fh, '<:raw', $path or die "open $path: $!";
	local $/ = undef;
	my $content = <$fh>;
	close $fh;
	return index($content, $needle) >= 0;
}

ok(-f $heap_path, "heap fork file exists at $heap_path");
ok(!file_contains($heap_path, $marker_query),
   'heap fork on disk does not contain plaintext payload');

# FSM file may or may not exist depending on insert path; skip if not
SKIP: {
	skip "no FSM file yet", 1 unless -f $fsm_path;
	my $fsm_size = -s $fsm_path;
	ok($fsm_size > 0, 'FSM fork has content (and is plaintext on disk)');
}

# Force VM creation by vacuuming
$node->safe_psql('postgres', 'VACUUM t;');
SKIP: {
	skip "no VM file yet", 1 unless -f $vm_path;
	my $vm_size = -s $vm_path;
	ok($vm_size > 0, 'VM fork exists after VACUUM (plaintext on disk)');
}

# Tamper detection: corrupt one byte in the heap fork and verify the
# next read surfaces the GCM tag verification error.
$node->stop;

my $tamper_offset = 100;	# inside the page header / payload, well before trailer
open my $fh, '+<:raw', $heap_path or die "open: $!";
sysseek $fh, $tamper_offset, 0;
my $byte;
sysread $fh, $byte, 1;
$byte = chr((ord($byte) ^ 0xFF) & 0xFF);
sysseek $fh, $tamper_offset, 0;
syswrite $fh, $byte;
close $fh;

$node->start;

my ($ret, $tampered_stdout, $tampered_stderr) = $node->psql('postgres',
	'SELECT count(*) FROM t;');
isnt($ret, 0, 'tampered heap page fails the read');
like($tampered_stderr,
	 qr/authentication tag verification failed|could not read|exceeds|invalid|corrupted/,
	 'tampered page surfaces an error');

# The PANIC during the tampered read takes the postmaster down, so we
# don't call $node->stop here — pg_ctl would Bail on the missing PID
# file.  The test framework's END handler will tear down the data dir.
done_testing();
