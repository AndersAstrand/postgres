# Copyright (c) 2026, PostgreSQL Global Development Group

if not ssl.found()
  subdir_done()
endif

sm4_file_encryption_sources = files(
  'sm4_file_encryption.c',
)

if host_system == 'windows'
  sm4_file_encryption_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'sm4_file_encryption',
    '--FILEDESC', 'sm4_file_encryption - SM4 reference file encryption module',])
endif

sm4_file_encryption = shared_module('sm4_file_encryption',
  sm4_file_encryption_sources,
  kwargs: contrib_mod_args + {
    'dependencies': [ssl, contrib_mod_args['dependencies']]
  },
)
contrib_targets += sm4_file_encryption

tests += {
  'name': 'sm4_file_encryption',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_buffile.pl',
      't/002_relation_pages.pl',
    ],
  },
}
