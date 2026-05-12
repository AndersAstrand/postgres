# Copyright (c) 2026, PostgreSQL Global Development Group

if not ssl.found()
  subdir_done()
endif

basic_file_encryption_sources = files(
  'basic_file_encryption.c',
)

if host_system == 'windows'
  basic_file_encryption_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'basic_file_encryption',
    '--FILEDESC', 'basic_file_encryption - reference file encryption module',])
endif

basic_file_encryption = shared_module('basic_file_encryption',
  basic_file_encryption_sources,
  kwargs: contrib_mod_args + {
    'dependencies': [ssl, contrib_mod_args['dependencies']]
  },
)
contrib_targets += basic_file_encryption

tests += {
  'name': 'basic_file_encryption',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_synthetic.pl',
    ],
  },
}
