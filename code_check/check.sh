#!/bin/bash

func(){
	echo "Usage:"
	echo "check.sh [-t TYPE] [-i DIFF] [-f FILE]"
	echo "Description:"
	echo "TYPE: would you like to \"check\" or \"fix\" "
	echo "DIFF: the number of diff that needs to be checked"
	echo "FILE: the file that needs to be checked or fixed"
	exit -1
}

TYPE_CHECK_LIST="ALLOC_ARRAY_ARGS,BLOCK_COMMENT_STYLE,ASSIGN_IN_IF,BOOL_COMPARISON,COMPARISON_TO_NULL,CONSTANT_COMPARISON,CODE_INDENT,DEEP_INDENTATION,SWITCH_CASE_INDENT_LEVEL,LONG_LINE,LONG_LINE_STRING,LONG_LINE_COMMENT,MULTILINE_DEREFERENCE,TRAILING_STATEMENTS,ARRAY_SIZE,INLINE_LOCATION,TRAILING_SEMICOLON,CAMELCASE,CONST_CONST,FUNCTION_ARGUMENTS,RETURN_PARENTHESES,ASSIGNMENT_CONTINUATIONS,BRACES,BRACKET_SPACE,CONCATENATED_STRING,ELSE_AFTER_BRACE,LINE_SPACING,OPEN_BRACE,POINTER_LOCATION,SPACING,TRAILING_WHITESPACE,WHILE_AFTER_BRACE"

while getopts 't:i:f:' OPT; do
	case $OPT in
		t) TYPE="$OPTARG";;
		i) 
			if [[ $OPTARG = -* ]]; then
			((OPTIND--))
			continue
			fi
			DIFF="$OPTARG";;
		f) 
			if [[ $OPTARG = -* ]]; then
				((OPTIND--))
				continue
			fi
			FILE="$OPTARG";;
		?) func;;
	esac
done


function check_diff (){
	(cd .. ; git diff "HEAD~${DIFF}") | ./checkpatch.pl --no-tree --max-line-length=180 --types "${TYPE_CHECK_LIST}"
}

function check_file(){
	./checkpatch.pl --no-tree --max-line-length=180 --types "${TYPE_CHECK_LIST}" -f "${FILE}"
}

function auto_fix_file(){
	./checkpatch.pl --no-tree --max-line-length=180 --types "${TYPE_CHECK_LIST}" --fix-inplace -f "${FILE}"
}

if [ $TYPE = "check" ] && [ -n "${DIFF}" ] 
then
	check_diff
elif [ $TYPE = "check" ] && [ -n "${FILE}" ]
then
	check_file
elif [ $TYPE = "fix" ] && [ -n "${FILE}" ]
then
	auto_fix_file
else
	func
fi
