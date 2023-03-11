# SPDX-License-Identifier: LGPL-2.1+

project('casync', 'c',
        version : '2',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
                'auto_features=enabled',
        ],
        meson_version : '>= 0.47')

cc = meson.get_compiler('c')

c_args = '''
        -Wextra
        -Werror=undef
        -Werror=format=2
        -Wformat-security
        -Wformat-nonliteral
        -Wlogical-op
        -Wmissing-include-dirs
        -Werror=old-style-definition
        -Werror=pointer-arith
        -Winit-self
        -Wfloat-equal
        -Wsuggest-attribute=noreturn
        -Werror=missing-prototypes
        -Werror=implicit-function-declaration
        -Werror=missing-declarations
        -Werror=return-type
        -Werror=incompatible-pointer-types
        -Werror=shadow
        -Werror=int-conversion
        -Wstrict-prototypes
        -Wredundant-decls
        -Wmissing-noreturn
        -Wendif-labels
        -Wstrict-aliasing=2
        -Wwrite-strings
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-result
        -Werror=overflow
        -Werror=sign-compare
        -Wdate-time
        -Wnested-externs
        -fno-common
        -fdiagnostics-show-option
        -fno-strict-aliasing
        -fvisibility=hidden
        -fstack-protector
        -fstack-protector-strong
        -fPIE
        --param=ssp-buffer-size=4
'''.split()

foreach arg : c_args
        if cc.has_argument(arg)
                add_project_arguments(arg, language : 'c')
        endif
endforeach

want_ossfuzz = get_option('oss-fuzz')
want_libfuzzer = get_option('llvm-fuzz')
if want_ossfuzz and want_libfuzzer
        error('only one of oss-fuzz and llvm-fuzz can be specified')
endif
fuzzer_build = want_ossfuzz or want_libfuzzer

add_languages('cpp', required : fuzzer_build)

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())

conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))

foreach ident : [
        ['renameat2',         '''#define _GNU_SOURCE
                                 #include <stdio.h>'''],
        ['copy_file_range',   '''#define _GNU_SOURCE
                                 #include <sys/syscall.h>
                                 #include <unistd.h>'''],
]
        have = cc.has_function(ident[0], args : '-D_GNU_SOURCE', prefix : ident[1])
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

if cc.has_function('getrandom', prefix : '''#include <sys/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', true)
        conf.set10('HAVE_GETRANDOM', true)
else
        conf.set10('USE_SYS_RANDOM_H', false)
        have = cc.has_function('getrandom', prefix : '''#include <linux/random.h>''')
        conf.set10('HAVE_GETRANDOM', have)
endif

############################################################

prefixdir = get_option('prefix')
bindir = join_paths(prefixdir, get_option('bindir'))
datadir = join_paths(prefixdir, get_option('datadir'))
docdir = join_paths(datadir, 'doc/casync')
protocoldir = join_paths(prefixdir, 'lib/casync/protocols')
conf.set_quoted('CASYNC_PROTOCOL_PATH', protocoldir)

liblzma = dependency(
        'liblzma',
        version : '>= 5.1.0',
        required : get_option('liblzma'))
conf.set10('HAVE_LIBLZMA', liblzma.found())

libz = dependency(
        'zlib',
        required : get_option('libz'))
conf.set10('HAVE_LIBZ', libz.found())

libzstd = dependency(
        'libzstd',
        version : '>= 0.8.1',
        required : get_option('libzstd'))
conf.set10('HAVE_LIBZSTD', libzstd.found())

libcurl = dependency('libcurl',
                     version : '>= 7.29.0')
openssl = dependency('openssl',
                     version : '>= 1.0')
libacl = cc.find_library('acl')

if get_option('fuse')
        libfuse = dependency('fuse',
                             version : '>= 2.6')
else
        libfuse = []
endif
conf.set10('HAVE_FUSE', get_option('fuse'))

if get_option('selinux')
        libselinux = dependency('libselinux')
else
        libselinux = []
endif
conf.set10('HAVE_SELINUX', get_option('selinux'))

if get_option('udev')
        libudev = dependency('libudev')
        udevrulesdir = get_option('udevrulesdir')
        if udevrulesdir == ''
                udev = dependency('udev', required : false)
                udevrulesdir = join_paths(udev.get_pkgconfig_variable('udevdir'), 'rules.d')
        endif
else
        libudev = []
endif
conf.set10('HAVE_UDEV', get_option('udev'))

threads = dependency('threads')
math = cc.find_library('m')

if want_libfuzzer
        fuzzing_engine = meson.get_compiler('cpp').find_library('Fuzzer')
elif want_ossfuzz
        fuzzing_engine = meson.get_compiler('cpp').find_library('FuzzingEngine')
endif

config_h = configure_file(
        output : 'config.h',
        configuration : conf)
add_project_arguments('-include', 'config.h', language : 'c')

subdir('src')
subdir('test')

includes = include_directories('src')

subdir('shell-completion/bash')
subdir('doc')

############################################################

casync = executable(
        'casync',
        casync_sources,
        link_with : libshared,
        dependencies : [
                libacl,
                libfuse,
                liblzma,
                libselinux,
                libudev,
                libz,
                libzstd,
                math,
                openssl],
        install : true)

casync_http = executable(
        'casync-http',
        casync_http_sources,
        link_with : libshared,
        dependencies : [
                libcurl,
                liblzma,
                libz,
                libzstd,
                math,
                openssl],
        install : true,
        install_dir : protocoldir)

meson.add_install_script('sh', '-c',
                         'ln -svf casync-http $DESTDIR@0@'.format(
                                 join_paths(protocoldir, 'casync-https')))
meson.add_install_script('sh', '-c',
                         'ln -svf casync-http $DESTDIR@0@'.format(
                                 join_paths(protocoldir, 'casync-ftp')))
meson.add_install_script('sh', '-c',
                         'ln -svf casync-http $DESTDIR@0@'.format(
                                 join_paths(protocoldir, 'casync-ftps')))
meson.add_install_script('sh', '-c',
                         'ln -svf casync-http $DESTDIR@0@'.format(
                                 join_paths(protocoldir, 'casync-sftp')))
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-https')
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-ftp')
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-ftps')
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-sftp')

############################################################

executable('notify-wait',
           notify_wait_sources,
           include_directories : includes,
           install : false)

############################################################

test_files_sh = find_program('test-files/test-files.sh')
run_target(
        'test-files',
        command : [test_files_sh, 'create'])
run_target(
        'clean-test-files',
        command : [test_files_sh, 'clean'])

substs = configuration_data()
substs.set_quoted('top_builddir', meson.build_root())
substs.set_quoted('top_srcdir', meson.source_root())
substs.set('bindir_unquoted', bindir)
substs.set10('HAVE_LIBLZMA', liblzma.found())
substs.set10('HAVE_LIBZ',    libz.found())
substs.set10('HAVE_LIBZSTD', libzstd.found())

test_script_sh = configure_file(
        output : 'test-script.sh',
        input : 'test/test-script.sh.in',
        configuration : substs)
test_script = find_program(test_script_sh)
test('test-script.sh', test_script,
     timeout : 30 * 60)

test_script_sha256_sh = configure_file(
        output : 'test-script-sha256.sh',
        input : 'test/test-script-sha256.sh.in',
        configuration : substs)
test_script_sha256 = find_program(test_script_sha256_sh)
test('test-script-sha256.sh', test_script_sha256,
     timeout : 30 * 60)

test_script_gzip_sh = configure_file(
        output : 'test-script-gzip.sh',
        input : 'test/test-script-gzip.sh.in',
        configuration : substs)
test_script_gzip = find_program(test_script_gzip_sh)
test('test-script-gzip.sh', test_script_gzip,
     timeout : 30 * 60)

test_script_xz_sh = configure_file(
        output : 'test-script-xz.sh',
        input : 'test/test-script-xz.sh.in',
        configuration : substs)
test_script_xz = find_program(test_script_xz_sh)
test('test-script-xz.sh', test_script_xz,
     timeout : 30 * 60)

test_nbd_sh = configure_file(
        output : 'test-nbd.sh',
        input : 'test/test-nbd.sh.in',
        configuration : substs)
test_nbd = find_program(test_nbd_sh)
test('test-nbd.sh', test_nbd,
     timeout : 30 * 60)

test_fuse_sh = configure_file(
        output : 'test-fuse.sh',
        input : 'test/test-fuse.sh.in',
        configuration : substs)
test_fuse = find_program(test_fuse_sh)
test('test-fuse.sh', test_fuse,
     timeout : 30 * 60)

test_cache_sh = configure_file(
        output : 'test-cache.sh',
        input : 'test/test-cache.sh.in',
        configuration : substs)
test_cache = find_program(test_cache_sh)
test('test-cache.sh', test_cache,
     timeout : 30 * 60)

udev_rule = configure_file(
          output : '75-casync.rules',
          input : 'src/75-casync.rules.in',
          configuration : substs)

if get_option('udev')
        install_data(udev_rule, install_dir : udevrulesdir)
endif

############################################################

test_sources = '''
        test-cachunk
        test-cachunker
        test-cachunker-histogram
        test-cadigest
        test-caencoder
        test-calocation
        test-camakebst
        test-camatch
        test-caorigin
        test-casync
        test-cautil
        test-feature-flags
        test-util
'''.split()

non_test_sources = '''
        test-caformat
        test-caindex
        test-calc-digest
'''.split()

test_dependencies = [
        libacl,
        liblzma,
        libselinux,
        libz,
        libzstd,
        math,
        openssl,
        threads]

foreach test_name : test_sources + non_test_sources
        exe = executable(
                test_name,
                'test/@0@.c'.format(test_name),
                include_directories : includes,
                link_with : libshared,
                dependencies : test_dependencies)

        if test_sources.contains(test_name)
                test(test_name, exe,
                     timeout : 3 * 60)
        endif
endforeach

fuzzer_exes = []

foreach tuple : fuzzers
        sources = tuple[0]

        deps = test_dependencies
        if fuzzer_build
                deps += fuzzing_engine
        else
                sources += fuzz_main_c
        endif

        name = sources[0].split('/')[-1].split('.')[0]

        fuzzer_exes += executable(
                name,
                sources,
                include_directories : [includes, include_directories('test/fuzz')],
                link_with : libshared,
                dependencies : deps,
                install : false)
endforeach

run_target('fuzzers',
        depends : fuzzer_exes,
        command : ['true'])

############################################################

meson_check_help = find_program('test/meson-check-help.sh')

foreach exec : [casync, casync_http]
        name = exec.full_path().split('/')[-1]
        test('check-help-' + name,
             meson_check_help,
             args : [exec.full_path()])
endforeach

############################################################

git = find_program('git', required : false)
if git.found()
        all_files = run_command(
                git,
                ['--git-dir=@0@/.git'.format(meson.source_root()),
                 'ls-files',
                 ':/*.[ch]'])
        all_files = files(all_files.stdout().split())

        run_target('tags',
                   command : ['env', 'etags', '-o', '@0@/@1@'.format(meson.source_root(), 'TAGS')] + all_files)
        run_target('ctags',
                   command : ['env', 'ctags', '-o', '@0@/@1@'.format(meson.source_root(), 'tags')] + all_files)
endif
