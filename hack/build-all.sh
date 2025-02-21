#!/bin/bash
set -e

# The passed parameter (could be "dev", branch name, or a version tag)
BUILD_REF="$1"

# Optionally, if BUILD_REF is "dev" you can generate the tag here
# or let container-build.sh handle it.
if [ "$BUILD_REF" == "dev" ]; then
  echo "Building dev images – dynamic tag will be computed."
fi

# Define an associative array mapping:
#  key: image repository path (used for tagging in the registry)
#  value: Docker build target (must match a stage in your Dockerfile)
declare -A images=(
  ["osc/onmetal/dp-service"]="production"
)

for img_path in "${!images[@]}"; do
  build_target=${images[$img_path]}
  echo "--------------------------------------"
  echo "Building image for repository path: ${img_path}"
  echo "Using Docker build target: ${build_target}"

  # Call the container-build script with:
  #  1. Registry path (img_mtr_path)
  #  2. The build reference (commit) – dynamic tag computed if needed inside container-build.sh
  #  3. Docker build target (which is also used for tagging)
  ./hack/container-build.sh "${img_path}" "${BUILD_REF}" "${build_target}"
done