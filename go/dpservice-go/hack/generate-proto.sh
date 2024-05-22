#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
# SPDX-License-Identifier: Apache-2.0

set -e

PROTOC_GEN_GO="$PROTOC_GEN_GO"
PROTOC_GEN_GO_GRPC="$PROTOC_GEN_GO_PROTOC_GEN_GO_GRPC"

BASEDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

DPSERVICE_DIR="../.."
cd "$DPSERVICE_DIR"
git describe --tags > ./go/dpservice-go/proto/generated_from.txt
cd ./go/dpservice-go/

echo "Generating protobuf"
export PATH="$PATH:$(dirname "$PROTOC_GEN_GO")"
export PATH="$PATH:$(dirname "$PROTOC_GEN_GO_GRPC")"
protoc --proto_path="$DPSERVICE_DIR" \
  --go_out="$BASEDIR"/.. \
  --go_opt=paths=source_relative \
  --go-grpc_out="$BASEDIR"/.. \
  --go-grpc_opt=paths=source_relative \
  "$DPSERVICE_DIR"/proto/dpdk.proto

for file in "$BASEDIR"/../proto/*.pb.go; do
  boilerplate="$(cat "$BASEDIR"/boilerplate.go.txt)"
  echo -e "$boilerplate\n$(cat "$file")" > "$file"
done
