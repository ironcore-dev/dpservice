#!/bin/bash

set -e

usage() {
	echo "Usage: $0 [-t TYPE] [-i DIFF | -f FILE] [-d]"
	echo ""
	echo "Options:"
	echo "  -t TYPE    mode of operation: \"check\" or \"fix\", default: \"check\""
	echo "  -i DIFF    number of commits to be checked"
	echo "  -f FILE    file to be checked or fixed"
	echo "  -d         download checkpatch.pl"
	echo ""
	echo "If no option specified, the whole branch will be checked from merge-base"
	exit 1
}

TYPE_CHECK_LIST="ALLOC_ARRAY_ARGS,BLOCK_COMMENT_STYLE,ASSIGN_IN_IF,BOOL_COMPARISON,COMPARISON_TO_NULL,CONSTANT_COMPARISON,CODE_INDENT,DEEP_INDENTATION,SWITCH_CASE_INDENT_LEVEL,LONG_LINE,LONG_LINE_STRING,LONG_LINE_COMMENT,MULTILINE_DEREFERENCE,TRAILING_STATEMENTS,ARRAY_SIZE,INLINE_LOCATION,TRAILING_SEMICOLON,CAMELCASE,CONST_CONST,FUNCTION_ARGUMENTS,RETURN_PARENTHESES,ASSIGNMENT_CONTINUATIONS,BRACES,BRACKET_SPACE,CONCATENATED_STRING,ELSE_AFTER_BRACE,LINE_SPACING,OPEN_BRACE,POINTER_LOCATION,SPACING,TRAILING_WHITESPACE,WHILE_AFTER_BRACE"
CHECKPATCH_OPTS="--no-tree --max-line-length=180 --types \"${TYPE_CHECK_LIST}\""
SCRIPT_DIR="$(dirname ${BASH_SOURCE})"
CHECKPATCH="${SCRIPT_DIR}/_checkpatch.pl"

function check_diff () {
	git -C "${SCRIPT_DIR}/.." diff "${DIFF}" | "${CHECKPATCH}" ${CHECKPATCH_OPTS}
}

function check_file() {
	"${CHECKPATCH}" ${CHECKPATCH_OPTS} -f "${FILE}"
}

function auto_fix_file() {
	"${CHECKPATCH}" ${CHECKPATCH_OPTS} --fix-inplace -f "${FILE}"
}

function download_checkpatch() {
	if [ -f "${CHECKPATCH}" ]; then
		echo "checkpatch.pl already present" >&2
		exit 1
	fi
	wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/checkpatch.pl -O "${CHECKPATCH}"
	chmod +x "${CHECKPATCH}"
	exit 1
}


TYPE="check"
DIFF="$(git -C "${SCRIPT_DIR}/.." merge-base main HEAD)"
while getopts 't:i:f:d' OPT; do
	case $OPT in
		t) TYPE="$OPTARG";;
		i) DIFF="HEAD~$OPTARG";;
		f) FILE="$OPTARG";;
		d) download_checkpatch;;
		?) usage;;
	esac
done

if [ ! -f "${CHECKPATCH}" ]; then
	echo "checkpatch.pl not present, use '$0 -d'" >&2
	exit 1
fi

if [ "${TYPE}" = "check" ] && [ -n "${DIFF}" ]; then
	check_diff
elif [ "${TYPE}" = "check" ] && [ -n "${FILE}" ]; then
	check_file
elif [ "${TYPE}" = "fix" ] && [ -n "${FILE}" ]; then
	auto_fix_file
else
	usage
fi

