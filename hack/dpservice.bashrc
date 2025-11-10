PATH="${PATH}:/"

source /etc/bash_completion
source <(dpservice-cli completion bash)

source ~/tcpdump_helpers.inc

if [ -z "${DP_FILE_PREFIX:-}" ]; then
	DP_FILE_PREFIX=dpservice
fi

if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	PS1='\[\033[01;31m\]\h\[\033[00m\] $DP_FILE_PREFIX \[\033[01;34m\]\w \$\[\033[00m\] '

	alias ls='ls --color=auto'

	alias grep='grep --color=auto'
	alias fgrep='fgrep --color=auto'
	alias egrep='egrep --color=auto'
else
	PS1='\h $DP_FILE_PREFIX \w \$ '
fi

HISTCONTROL=ignoredups
