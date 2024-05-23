#!/bin/bash

set -e

cd "$(dirname "$0")"

make build

mkdir -p ../../build/cli/dpservice-cli

mv bin/dpservice-cli ../../build/cli/dpservice-cli
