" 'set exrc' in ~/.vimrc will read .vimrc from the current directory
" Warning: Enabling exrc is dangerous! You can do nearly everything from a
" vimrc configuration file, including write operations and shell execution.
" You should consider setting 'set secure' as well, which is highly
" recommended!

" NOTE: If you update this file make sure to update .dir-locals.el and
" .editorconfig, too.

set tabstop=8
set shiftwidth=8
set expandtab
set makeprg=GCC_COLORS=\ make
set tw=79
au BufRead,BufNewFile *.xml set tw=109 shiftwidth=2 smarttab
au FileType c set tw=109
