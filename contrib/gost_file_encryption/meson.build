# Copyright (c) 2026, PostgreSQL Global Development Group

if not ssl.found()
  subdir_done()
endif

gost_file_encryption_sources = files(
  'gost_file_encryption.c',
)

if host_system == 'windows'
  gost_file_encryption_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'gost_file_encryption',
    '--FILEDESC', 'gost_file_encryption - GOST reference file encryption module',])
endif

gost_file_encryption = shared_module('gost_file_encryption',
  gost_file_encryption_sources,
  kwargs: contrib_mod_args + {
    'dependencies': [ssl, contrib_mod_args['dependencies']]
  },
)
contrib_targets += gost_file_encryption

tests += {
  'name': 'gost_file_encryption',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_buffile.pl',
    ],
  },
}
