#!/bin/bash
set -e
start=$(date +%s)
function timing() {
  end=$(date +%s)
  echo "Container build time was $((end - start)) seconds."
}
trap timing EXIT

# Enable BuildKit for cache mount support in Dockerfile
export DOCKER_BUILDKIT=1

# Allow switching between docker and podman (default is docker)
CONTAINER_CLI=${CONTAINER_CLI:-docker}

cd "$GOPATH" || exit

img_mtr_path=$1    # e.g. "osc/iaas/dpservice"
commit=$2          # "dev", branch name, or version tag
docker_target=$3   # e.g. "production"

# Normalize branch names: replace slashes with dashes (e.g. feature/foo -> feature-foo)
# Docker tags do not allow slashes.
commit=${commit//\//-}

cd "${GOPATH}/src/${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git"

LABEL=""
# If commit equals "dev", replace it with dynamic tag
if [ "$commit" == "dev" ]; then
  LABEL='--label quay.expires-after=30d'
  commit=$(date +%d%m%Y)-$(git rev-parse --short HEAD)
else
  commit=${commit}-$(git rev-parse --short HEAD)
fi

if [[ "$commit" =~ ^(feature-.*|feat-.*|bugfix-.*|fix-.*|v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.ci-.*) ]]; then
    LABEL='--label quay.expires-after=30d'
fi

echo "Using label: $LABEL"

$CONTAINER_CLI build \
  --build-arg CI_JOB_TOKEN="${CI_JOB_TOKEN}" \
  --build-arg DPDK_BUILDTYPE="debugoptimized" \
  --build-arg DPSERVICE_BUILDTYPE="debugoptimized" \
  --build-arg DPSERVICE_FEATURES="-Denable_virtual_services=true -Denable_underlay_type=true" \
  --build-arg DPSERVICE_VERSION="$commit" \
  --build-arg OSC_BUILD_COMMIT_SHA="${CI_COMMIT_SHA}" \
  $LABEL \
  --build-arg CI_SERVER_HOST="${CI_SERVER_HOST}" \
  --build-arg CI_PROJECT_PATH="${CI_PROJECT_PATH}" \
  --tag "$docker_target:$commit" \
  --target "$docker_target" \
  -f Dockerfile .

$CONTAINER_CLI tag "$docker_target:$commit" "${MTR_GITLAB_HOST}/$img_mtr_path:$commit"
$CONTAINER_CLI login -u "$MTR_GITLAB_LOGIN" -p "$MTR_GITLAB_PASSWORD" "$MTR_GITLAB_HOST"
$CONTAINER_CLI push "${MTR_GITLAB_HOST}/$img_mtr_path:$commit"

echo "Docker target: $docker_target"
echo "Commit/Tag: $commit"
echo "MTR_GITLAB_HOST: ${MTR_GITLAB_HOST}"
echo "Image registry path: $img_mtr_path"
echo "Tagging: ${CI_PROJECT_NAME}:$commit as ${MTR_GITLAB_HOST}/$img_mtr_path:$commit"
echo "Pushing: ${MTR_GITLAB_HOST}/$img_mtr_path:$commit"

# Sign image in MTR based on its digest
source ./hack/cosign-main.sh
cosign-main "$img_mtr_path" "$commit"
