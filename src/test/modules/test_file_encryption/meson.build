# Copyright (c) 2026, PostgreSQL Global Development Group

test_file_encryption_sources = files(
  'test_file_encryption.c',
)

if host_system == 'windows'
  test_file_encryption_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'test_file_encryption',
    '--FILEDESC', 'test_file_encryption - test file encryption module',])
endif

test_file_encryption = shared_module('test_file_encryption',
  test_file_encryption_sources,
  kwargs: pg_test_mod_args,
)
test_install_libs += test_file_encryption

tests += {
  'name': 'test_file_encryption',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_buffile.pl',
      't/002_logical_decoding.pl',
      't/003_corruption.pl',
      't/004_apply_streaming.pl',
    ],
  },
}
