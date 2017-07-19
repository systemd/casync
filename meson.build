project('casync', 'c',
        version : '0.1',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu99',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
        ],
        meson_version : '>= 0.40')

cc = meson.get_compiler('c')

c_args = '''
        -Wextra
        -Werror=undef
        -Wformat=2 -Wformat-security -Wformat-nonliteral
        -Wlogical-op
        -Wmissing-include-dirs
        -Wold-style-definition
        -Wpointer-arith
        -Winit-self
        -Wdeclaration-after-statement
        -Wfloat-equal
        -Wsuggest-attribute=noreturn
        -Werror=missing-prototypes
        -Werror=implicit-function-declaration
        -Werror=missing-declarations
        -Werror=return-type
        -Werror=shadow
        -Wstrict-prototypes
        -Wredundant-decls
        -Wmissing-noreturn
        -Wshadow
        -Wendif-labels
        -Wstrict-aliasing=2
        -Wwrite-strings
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-result
        -Wno-format-signedness
        -Werror=overflow
        -Wdate-time
        -Wnested-externs
        -ffast-math
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

conf = configuration_data()
conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))

foreach ident : [
        ['renameat2',         '''#include <stdio.h>'''],
        ['copy_file_range',   '''#include <sys/syscall.h>
                                 #include <unistd.h>'''],
]
        have = cc.has_function(ident[0], prefix : ident[1])
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

liblzma = dependency('liblzma',
                     version : '>= 5.1.0')
libcurl = dependency('libcurl',
                     version : '>= 7.32.0')
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

threads = dependency('threads')
math = cc.find_library('m')

config_h = configure_file(
        output : 'config.h',
        configuration : conf)
add_project_arguments('-include', 'config.h', language : 'c')

subdir('src')
subdir('test')

includes = include_directories('src')

udevlibexecdir = join_paths(prefixdir, 'lib/udev')
udevrulesdir = join_paths(udevlibexecdir, 'rules.d')

subdir('doc')

############################################################

executable(
        'casync',
        casync_sources,
        link_with : libshared,
        dependencies : [
                liblzma,
                openssl,
                libacl,
                libfuse,
                math],
        install : true)

executable(
        'casync-http',
        casync_http_sources,
        link_with : libshared,
        dependencies : [
                liblzma,
                openssl,
                libcurl,
                math],
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
                                 join_paths(protocoldir, 'casync-sftp')))
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-https')
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-ftp')
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

udev_rule = configure_file(
          output : '75-casync.rules',
          input : 'src/75-casync.rules.in',
          configuration : substs)

install_data(udev_rule, install_dir : udevrulesdir)

############################################################

test_sources = '''
        test-cachunk
        test-cachunker
        test-cachunker-histogram
        test-cadigest
        test-caencoder
        test-camakebst
        test-caorigin
        test-casync
        test-cautil
        test-util
'''.split()

non_test_sources = '''
        test-caformat
        test-caindex
        test-calc-digest
'''.split()

foreach test_name : test_sources + non_test_sources
        exe = executable(
                test_name,
                'test/@0@.c'.format(test_name),
                link_with : libshared,
                include_directories : includes,
                dependencies : [
                        liblzma,
                        openssl,
                        libacl,
                        threads,
                        math])

        if test_sources.contains(test_name)
                test(test_name, exe,
                     timeout : 2 * 60)
        endif
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
