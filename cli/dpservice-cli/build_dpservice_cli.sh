#!/bin/bash

set -e

cd "$(dirname "$0")"

make build

mkdir -p ../build

mv bin/dpservice-cli ../build/
