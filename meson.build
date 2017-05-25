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

add_project_arguments(c_args, language : 'c')

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

conf.set10('HAVE_STRUCT_FILE_CLONE_RANGE',
           cc.has_header_symbol('linux/fs.h', 'struct file_clone_range'))

############################################################

prefixdir = get_option('prefix')
datadir = join_paths(prefixdir, get_option('datadir'))
docdir = join_paths(datadir, 'doc/casync')
protocoldir = join_paths(prefixdir, 'lib/casync/protocols')
conf.set_quoted('CASYNC_PROTOCOL_PATH', protocoldir)

liblzma = dependency('liblzma',
                     version : '>= 5.1.0')
libcurl = dependency('libcurl',
                     version : '>= 7.32.0')

libgcrypt = cc.find_library('gcrypt')
libacl = cc.find_library('acl')

if get_option('fuse')
        libfuse = dependency('fuse',
                             version : '>= 2.6')
else
        libfuse = []
endif
conf.set10('HAVE_FUSE', get_option('fuse'))

config_h = configure_file(
        output : 'config.h',
        configuration : conf)
add_project_arguments('-include', 'config.h', language : 'c')

subdir('src')

includes = include_directories('src')

############################################################

executable(
        'casync',
        casync_sources,
        link_with : libshared,
        dependencies : [
                liblzma,
                libgcrypt,
                libacl,
                libfuse],
        install : true)

executable(
        'casync-http',
        casync_http_sources,
        link_with : libshared,
        dependencies : [
                liblzma,
                libgcrypt,
                libcurl],
        install : true,
        install_dir : protocoldir)

meson.add_install_script('sh', '-c',
                         'ln -svf casync-http $DESTDIR@0@'.format(
                                 join_paths(protocoldir, 'casync-https')))
meson.add_install_script('sh', '-c',
                         'ln -svf casync-http $DESTDIR@0@'.format(
                                 join_paths(protocoldir, 'casync-ftp')))
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-https')
meson.add_postconf_script('sh', '-c',
                         'ln -svf casync-http $MESON_BUILD_ROOT/casync-ftp')

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

test_script_sh = configure_file(
        output : 'test-script.sh',
        input : 'test/test-script.sh.in',
        configuration : substs)
test_script = find_program(test_script_sh)
test('test-script.sh', test_script,
     timeout : 300)

test_nbd_sh = configure_file(
        output : 'test-nbd.sh',
        input : 'test/test-nbd.sh.in',
        configuration : substs)
test_nbd = find_program(test_nbd_sh)
test('test-nbd.sh', test_nbd)

test_fuse_sh = configure_file(
        output : 'test-fuse.sh',
        input : 'test/test-fuse.sh.in',
        configuration : substs)
test_fuse = find_program(test_fuse_sh)
test('test-fuse.sh', test_fuse)

############################################################

test_sources = '''
        test-cachunk
        test-cachunker
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
'''.split()

foreach test_name : test_sources + non_test_sources
        exe = executable(
                test_name,
                'test/@0@.c'.format(test_name),
                link_with : libshared,
                include_directories : includes,
                dependencies : [
                        liblzma,
                        libgcrypt,
                        libacl])

        if test_sources.contains(test_name)
                test(test_name, exe)
        endif
endforeach
