#!/bin/bash

set -e

function die() {
	echo "ERROR: $1" 1>&2
	exit 1
}

[ -z "$MTR_GITLAB_LOGIN" ] && die "Unset MTR_GITLAB_LOGIN"
[ -z "$MTR_GITLAB_HOST" ] && die "Unset MTR_GITLAB_HOST"
[ -z "$MTR_GITLAB_PASSWORD" ] && die "Unset MTR_GITLAB_PASSWORD"

DOCKER_CRE=podman # or docker

COMMITID=$(git rev-parse --short HEAD)
#COMMITDATE=$(git show -s --format=%cd --date=format:'%d%m%Y' $COMMITID)
COMMITDATE=$(date +%d%m%Y)
TAG="$MTR_GITLAB_HOST/osc/onmetal/dp-service:$COMMITDATE-$COMMITID"

echo "$MTR_GITLAB_PASSWORD" | $DOCKER_CRE login --username "$MTR_GITLAB_LOGIN" --password-stdin "$MTR_GITLAB_HOST"

$DOCKER_CRE build --platform=linux/amd64 --build-arg="DPSERVICE_FEATURES=-Denable_virtual_services=true" -t "$TAG" .

$DOCKER_CRE push "$TAG"
$DOCKER_CRE logout "$MTR_GITLAB_HOST"

# uncomment this if you want to reconfigure MTR image as public; then also MTR_GITLAB_TOKEN needs to be defined
#curl -H "Authorization: Bearer $MTR_GITLAB_TOKEN" -H 'Content-Type: application/json' -XPOST https://${MTR_GITLAB_HOST}/api/v1/repository/${target_basename}/changevisibility -d '{"visibility": "public"}'
