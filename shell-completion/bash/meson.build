# SPDX-License-Identifier: LGPL-2.1+

bashcompletiondir = get_option('bashcompletiondir')
if bashcompletiondir == ''
        bash_completion = dependency('bash-completion', required : false)
        if bash_completion.found()
                bashcompletiondir = bash_completion.get_pkgconfig_variable('completionsdir')
        else
                bashcompletiondir = join_paths(datadir, 'bash-completion/completions')
        endif
endif

if bashcompletiondir != 'no'
        install_data('casync', install_dir : bashcompletiondir)
endif
