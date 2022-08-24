A script is provided to simplify the usage of checkpatch.pl to perform code polishing. It is useful, especially when a subset of checking types shall be considered during the checking process. In order to use this script, firstly download checkpatch.pl by following this [link](https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl), and put it into this directory. This script currently supports three functions:

1) check last n commit:

	`./check.sh -t check  -i n`

2) check single file PATH_TO_ILE:
 	
	`./check.sh -t check -f PATH_TO_ILE`

3) auto fix single file PATH_TO_ILE:
	
	`./check.sh -t fix  -f PATH_TO_ILE`

