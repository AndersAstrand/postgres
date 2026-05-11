# Copyright (c) 2026, PostgreSQL Global Development Group

# Verify two cross-cutting paths for page encryption:
#   1) Unlogged tables survive crash reinit -- the KEY fork is preserved
#      across the reinit pass so the relation remains decryptable after
#      the (empty) reset state is filled with new rows.
#   2) Base backups include the KEY fork (alongside the init fork) for
#      unlogged relations, so a restored cluster can read pages written
#      after restart.

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

my $primary = PostgreSQL::Test::Cluster->new('primary');
$primary->init(extra => ['--file-encryption-page-reserved-size=32',
						 '-c', 'file_encryption_library=basic_file_encryption',
						 '-c', "basic_file_encryption.key=$key"],
			   allows_streaming => 1);
$primary->append_conf('postgresql.conf', qq[
file_encryption_library = 'basic_file_encryption'
basic_file_encryption.key = '$key'
]);
$primary->start;

# Create an unlogged relation and populate it.
$primary->safe_psql('postgres', q[
CREATE UNLOGGED TABLE u (id int PRIMARY KEY, payload text);
INSERT INTO u SELECT g, 'unlogged-' || g FROM generate_series(1, 1000) g;
CHECKPOINT;
]);

is($primary->safe_psql('postgres', 'SELECT count(*) FROM u;'), '1000',
   'unlogged table populated before crash');

# Force a crash so reinit runs on restart.  The relation's MAIN fork
# gets wiped and re-seeded from INIT.  We need the KEY fork to survive
# so the post-restart writes can encrypt under the same DEK.
$primary->stop('immediate');
$primary->start;

# The relation should be empty after reinit, and writable.
is($primary->safe_psql('postgres', 'SELECT count(*) FROM u;'), '0',
   'unlogged table reset to empty after crash');
$primary->safe_psql('postgres', q[
INSERT INTO u SELECT g, 'after-reset-' || g FROM generate_series(1, 50) g;
CHECKPOINT;
]);
is($primary->safe_psql('postgres', 'SELECT count(*) FROM u;'), '50',
   'unlogged table writable after reset (DEK survived reinit)');
my $sample = $primary->safe_psql('postgres',
	"SELECT payload FROM u WHERE id = 7;");
is($sample, 'after-reset-7', 'post-reset tuple round-trips through encryption');

# Take a base backup and restore it.  The KEY fork of the unlogged
# relation must be included so the restored cluster can encrypt new
# writes under the same DEK that was used to re-seed.
my $backup_path = $primary->backup_dir . '/backup-with-unlogged';
$primary->backup('backup-with-unlogged');

my $restored = PostgreSQL::Test::Cluster->new('restored');
$restored->init_from_backup($primary, 'backup-with-unlogged');
$restored->append_conf('postgresql.conf', qq[
file_encryption_library = 'basic_file_encryption'
basic_file_encryption.key = '$key'
]);
$restored->start;

# The unlogged relation is empty (init fork copied to main on start),
# but writable; encryption is engaged.
is($restored->safe_psql('postgres', 'SELECT count(*) FROM u;'), '0',
   'restored unlogged table is empty');
$restored->safe_psql('postgres', q[
INSERT INTO u SELECT g, 'restored-' || g FROM generate_series(1, 25) g;
CHECKPOINT;
]);
is($restored->safe_psql('postgres', 'SELECT count(*) FROM u;'), '25',
   'restored unlogged table writable (KEY fork made it into backup)');

$primary->stop;
$restored->stop;
done_testing();
