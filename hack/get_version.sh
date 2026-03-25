#!/bin/bash

# Allow overriding the version via environment variable
if [ -n "$DPSERVICE_VERSION" ]; then
    echo "$DPSERVICE_VERSION"
    exit 0
fi

# For non-tagged commits, this is a simple "vX.X.X-XX-gXXXXXXX"
# For dpservice-bin tagged commits, this is "vX.X.X"
# For dpservice-go tagged commits, this is "go/dpservice-go/vX.X.X-XX-gXXXXXXX"
GITVER=$(git describe --tags --always)

# The solution is to simply print the last item of an array created by splitting the Git version
ARRAY=(${GITVER//\// })
echo ${ARRAY[*]: -1}
