# SPDX-License-Identifier: LGPL-2.1+

sphinx_sources = [
        'conf.py',
        'casync.rst',
        'index.rst']

man_pages = [
        'casync.1']

mandir1 = join_paths(get_option('mandir'), 'man1')

if get_option('man')
        sphinx_build = find_program('sphinx-build-3', 'sphinx-build')

        custom_target(
                'man',
                command : [sphinx_build,
                           '-b', 'man',
                           meson.current_source_dir(),
                           meson.current_build_dir()],
                input : sphinx_sources,
                output : man_pages,
                install : true,
                install_dir : mandir1)
endif
