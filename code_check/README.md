A script is provided to simplify the usage of checkpatch.pl to perform code polishing. It is useful, especially when a subset of checking types shall be considered during the checking process.

In order to use this script, download checkpatch.pl by calling `./check.sh -d`. You can also download one yourself from [this link](https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl), and put it into this directory as `_checkpatch.pl`.

Currently supported functions:
1) Check all commits since merge-base:

	`./check.sh`

2) Check last n commits:

	`./check.sh -i n`

3) Check a single file:
 	
	`./check.sh -f PATH_TO_FILE`

4) Auto-fix a single file:
	
	`./check.sh -t fix -f PATH_TO_FILE`

