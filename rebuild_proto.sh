#!/bin/sh

if [ -z "$GOPATH" ]; then
    GOPATH=$HOME/go
fi

TRILLIAN=$GOPATH/src/github.com/google/trillian

PROTOC="python3 -m grpc_tools.protoc"
# can't change this without breaking imports
OUTDIR=.
# copy locally for convenience
mkdir -p $OUTDIR/proto
cp $TRILLIAN/*.proto $TRILLIAN/crypto/keyspb/*.proto $TRILLIAN/crypto/sigpb/*.proto $OUTDIR/proto

$PROTOC -I$TRILLIAN -I$GOPATH/src/github.com/googleapis/googleapis --python_out=$OUTDIR --grpc_python_out=$OUTDIR $TRILLIAN/*.proto $TRILLIAN/crypto/keyspb/*.proto $TRILLIAN/crypto/sigpb/*.proto
$PROTOC -I$GOPATH/src/github.com/googleapis/googleapis --python_out=$OUTDIR $GOPATH/src/github.com/googleapis/googleapis/google/api/*.proto $GOPATH/src/github.com/googleapis/googleapis/google/rpc/*.proto
