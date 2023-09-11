#!/bin/bash
# This script uses a Personal Access Token (PAT) to access a GitHub repository.
# It takes the following parameters in the style "-parameter=PARAMETER_VALUE":
# 1. -dir : Destination directory. A directory path (relative to the current directory) where the files will be downloaded.
# 2. -owner : Repository owner. The username of the owner of the repository on GitHub.
# 3. -repo : Repository name. The name of the repository on GitHub.
# 4. -pat : Personal Access Token (PAT). A token provided by GitHub to access the repository.
# 5. -release : (Optional) Release tag. By default, it is set to "latest".
# Example usage:
# ./hack/rel_download.sh -dir=exporter -owner=onmetal -repo=prometheus-dpdk-exporter -pat=MY_PAT

set -e

if [ "$#" -lt 4 ]; then
	echo "Usage: $0 -dir=<Destination Directory> -owner=<Repository Owner> -repo=<Repository Name> -pat=<Personal Access Token> [-release=<Release Tag>]"
	exit 1
fi

# Process parameters
STRIPTAR="0"
for i in "$@"
do
case $i in
	-dir=*)
	DIRECTORY="${i#*=}"
	shift
	;;
	-owner=*)
	REPO_OWNER="${i#*=}"
	shift
	;;
	-repo=*)
	REPO_NAME="${i#*=}"
	shift
	;;
	-pat=*)
	PAT="${i#*=}"
	shift
	;;
	-release=*)
	RELEASE="${i#*=}"
	shift
	;;
	-strip=*)
	STRIPTAR="${i#*=}"
	shift
	;;
	*)
	# unknown option
	;;
esac
done

RELEASE=${RELEASE:-latest}

if [ ! -d "$DIRECTORY" ]; then
	mkdir -p "$DIRECTORY"
fi

if [ -z "$PAT" ]; then
	touch $DIRECTORY/dummy_$DIRECTORY
	echo "No PAT defined. Will not download the packages"
	exit 0
fi

# Use curl to access the GitHub API and get the asset ID.
ASSET_ID=$(curl -s -L -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $PAT" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/$RELEASE | jq -r '.assets[] | select (.name | contains("linux_amd64")) | .id')

if [ -z "$ASSET_ID" ]; then
	echo "Failed to copy the release binary to $DIRECTORY"
	exit 1
fi

# Use curl to download the asset using the asset ID.
curl -s -L -H "Accept: application/octet-stream" -H "Authorization: Bearer $PAT" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/assets/$ASSET_ID -o $DIRECTORY/$DIRECTORY.tar.gz

tar -xzf $DIRECTORY/$DIRECTORY.tar.gz -C $DIRECTORY --strip-components $STRIPTAR
rm $DIRECTORY/$DIRECTORY.tar.gz
rm -rf $DIRECTORY/LICENSE*
rm -rf $DIRECTORY/README.md

if [ "$?" -eq 0 ]; then
	echo "Release binary successfully copied to $DIRECTORY"
else
	echo "Failed to copy the release binary to $DIRECTORY"
	exit 1
fi

exit 0
