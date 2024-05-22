#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

NET_DPSERVICE_REVISION="main"

set -e

PROTOC_GEN_GO="$PROTOC_GEN_GO"
PROTOC_GEN_GO_GRPC="$PROTOC_GEN_GO_PROTOC_GEN_GO_GRPC"

BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

NET_DPSERVICE_DIR="$(mktemp -d)"
trap 'rm -rf $NET_DPSERVICE_DIR' EXIT

function clone() {
  cd "$NET_DPSERVICE_DIR"
  git init
  git remote add origin git@github.com:ironcore-dev/dpservice.git
  git fetch origin "$NET_DPSERVICE_REVISION" --depth=1
  git reset --hard FETCH_HEAD
  git fetch --prune --unshallow
  git describe --tags > version.txt
}

echo "Cloning repository"
if ! err="$(clone 2>&1)"; then
  echo "Error cloning repository:"
  echo "$err"
fi

cp $NET_DPSERVICE_DIR/version.txt ./proto/generated_from.txt

echo "Generating protobuf"
export PATH="$PATH:$(dirname "$PROTOC_GEN_GO")"
export PATH="$PATH:$(dirname "$PROTOC_GEN_GO_GRPC")"
protoc --proto_path="$NET_DPSERVICE_DIR" \
  --go_out="$BASEDIR"/.. \
  --go_opt=paths=source_relative \
  --go-grpc_out="$BASEDIR"/.. \
  --go-grpc_opt=paths=source_relative \
  "$NET_DPSERVICE_DIR"/proto/dpdk.proto

for file in "$BASEDIR"/../proto/*.pb.go; do
  boilerplate="$(cat "$BASEDIR"/boilerplate.go.txt)"
  echo -e "$boilerplate\n$(cat "$file")" > "$file"
done
