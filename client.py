#!/usr/bin/env python3

import argparse
from hashlib import sha256
import ecdsa
import grpc
import time
import struct
import os
import time
from binascii import hexlify

import util
from google.protobuf.duration_pb2 import Duration
from trillian_pb2 import Tree, LOG, ACTIVE, RFC6962_SHA256
from trillian_admin_api_pb2 import ListTreesRequest, CreateTreeRequest, DeleteTreeRequest
from trillian_log_api_pb2 import (
    LogLeaf,
    GetLatestSignedLogRootRequest,
    QueueLeafRequest,
    QueueLeavesRequest,
    GetLeavesByIndexRequest,
    GetConsistencyProofRequest,
    GetInclusionProofByHashRequest,
)
from trillian_admin_api_pb2_grpc import TrillianAdminStub
from trillian_log_api_pb2_grpc import TrillianLogStub
from crypto.sigpb.sigpb_pb2 import DigitallySigned
from crypto.keyspb.keyspb_pb2 import Specification


class TrillianLogClient():
    """References:
    https://github.com/google/trillian/blob/master/client/client.go
    https://github.com/google/trillian/blob/master/merkle/log_verifier.go
    """
    def __init__(self, endpoint, reset=False):
        channel = grpc.insecure_channel(endpoint)
        self.admin_stub = TrillianAdminStub(channel)
        self.log_stub = TrillianLogStub(channel)
        if reset:
            self._delete_all()
            self.log = self._create_log()
            # TODO: wait for log to initialize
        else:
            self.log = self._list_trees().tree[0]

    def _list_trees(self, show_deleted=False):
        return self.admin_stub.ListTrees(ListTreesRequest(show_deleted=show_deleted))

    def _create_log(self):
        # field signature_cipher_suite=DigitallySigned.ECDSA_SHA256 does't do anything (yet)
        tree = Tree(
            tree_type=LOG,
            tree_state=ACTIVE,
            max_root_duration=Duration(seconds=0, nanos=0),
            hash_strategy=RFC6962_SHA256,
            hash_algorithm=DigitallySigned.SHA256,
            signature_algorithm=DigitallySigned.ECDSA)
        request = CreateTreeRequest(
            tree=tree,
            key_spec=Specification(ecdsa_params=Specification.ECDSA(curve=Specification.ECDSA.P256)))
        return self.admin_stub.CreateTree(request)

    def _delete_all(self):
        for tree in self._list_trees().tree:
            self.admin_stub.DeleteTree(DeleteTreeRequest(tree_id=tree.tree_id))

    def get_and_verify_root(self):
        root = self.log_stub.GetLatestSignedLogRoot(GetLatestSignedLogRootRequest(log_id=self.log.tree_id)).signed_log_root
        if not root.signature.signature:
            raise ValueError('empty signature (wait a bit after creating new log?)')
        assert root.signature.hash_algorithm == DigitallySigned.SHA256
        assert root.signature.signature_algorithm == DigitallySigned.ECDSA
        public_key = ecdsa.VerifyingKey.from_der(self.log.public_key.der)
        public_key.verify(root.signature.signature, util.hash_tree_root(root), hashfunc=sha256, sigdecode=ecdsa.util.sigdecode_der)
        return root

    def get_all_entries(self, root, batch_size=1000):
        # leaf_index is 0-indexed
        result = []
        root = self.get_and_verify_root()
        size = root.tree_size
        for i in range(0, size, batch_size):
            request = GetLeavesByIndexRequest(log_id=self.log.tree_id, leaf_index=range(i, min(size, i + batch_size)))
            leaves = self.log_stub.GetLeavesByIndex(request).leaves
            # result might not be ordered (!)
            result += sorted(leaves, key=lambda x: x.leaf_index)
        assert len(result) == size
        # have all the leaves, might as well verify :P
        if util.hash_leaves(result) != root.root_hash:
            raise ValueError('hash of all leaves does not match root hash')
        return result

    def test_inclusion_proofs(self):
        """Check that inclusion proofs are handled properly.
        This function essentially does the same as get_all_entries
        but does much more work: don't call in a real application.
        """
        root = self.get_and_verify_root()
        leaves = self.get_all_entries(root)
        for leaf in leaves:
            self.verify_inclusion(root, leaf)

    def audit(self):
        # note: tree_revision is 1-indexed, and no API call takes it
        # TODO
        raise NotImplementedError('audit not implemented')

        root = self.get_and_verify_root()
        size = root.tree_size
        # revision = root.tree_revision
        # print('latest revision: {}'.format(revision))
        if size > 0:
            request = GetConsistencyProofRequest(log_id=self.log.tree_id, first_tree_size=1, second_tree_size=size)
            print(self.log_stub.GetConsistencyProof(request))
        else:
            print('no entries in log')

    def append(self, leaf):
        return self.log_stub.QueueLeaf(QueueLeafRequest(log_id=self.log.tree_id, leaf=leaf))

    def verify_inclusion(self, root, leaf):
        size = root.tree_size
        leaf_hash = util.hash_leaf(leaf)
        if size == 0:
            raise ValueError('log is empty')
        if size == 1:
            if leaf_hash != root.root_hash:
                raise ValueError('leaf hash does not match root hash')
            return
        request = GetInclusionProofByHashRequest(log_id=self.log.tree_id, leaf_hash=leaf_hash, tree_size=root.tree_size)
        response = self.log_stub.GetInclusionProofByHash(request)
        assert len(response.proof) == 1
        proof = response.proof[0]
        branch = [] # 0: merge (leaf, proof_rest); 1: merge (proof_rest, leaf)
        n = proof.leaf_index
        while size > 1:
            k = util.next_smaller_pow2(size)
            if n < k:
                branch.append(0)
                size = k
            else:
                branch.append(1)
                n -= k
                size -= k
        assert len(branch) == len(proof.hashes)
        overall_hash = leaf_hash
        for i, b in enumerate(branch[::-1]):
            h = proof.hashes[i]
            if b == 0:
                overall_hash = util.hash_pair_hashes(overall_hash, h)
            else:
                overall_hash = util.hash_pair_hashes(h, overall_hash)
        if overall_hash != root.root_hash:
            raise ValueError('inclusion proof fail')

    def append_batch(self, leaves):
        return self.log_stub.QueueLeaves(QueueLeavesRequest(log_id=self.log.tree_id, leaves=leaves))


def main():
    """
    MySQL:
        docker run --rm -p 127.0.0.1:3306:3306 --name mysql -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_ROOT_PASSWORD= -d mysql

    need to set env MYSQL_HOST=127.0.0.1
    and replace '${DB_NAME}'@'localhost' with '${DB_NAME}'@'%' in scripts/resetdb.sh

    To run log server:
        ./trillian_log_server -logtostderr
        ./trillian_log_signer -logtostderr -force_master -http_endpoint "" -batch_size 10000 -sequencer_interval 2s
    """
    parser = argparse.ArgumentParser(description='interact with Trillian')
    parser.add_argument('--reset', action='store_true', help='delete all trees')
    parser.add_argument('--benchmark', action='store_true', help='benchmark')
    parser.add_argument('--append', action='store_true', help='append a random entry')
    parser.add_argument('--test', action='store_true', help='test inclusion proofs')
    args = parser.parse_args()

    client = TrillianLogClient('localhost:8090', reset=args.reset)

    if args.benchmark:
        start = time.time()
        # break up request to avoid hitting max size
        for _ in range(10):
            leaves = (LogLeaf(leaf_value=os.urandom(32)) for _ in range(10000))
            client.append_batch(leaves)
        diff = time.time() - start
        print('{} sec'.format(diff))
    elif args.append:
        leaf = LogLeaf(leaf_value=os.urandom(32))
        root = client.get_and_verify_root()
        print(client.append(leaf))
        for _ in range(10):
            time.sleep(1)
            new_root = client.get_and_verify_root()
            if new_root.tree_size > root.tree_size:
                break
        else:
            raise Exception('no new root')
        root = new_root
        # possible for leaf to not actually be included in log at this point
        # but w/e
        client.verify_inclusion(root, leaf)
    if args.test:
        client.test_inclusion_proofs()

    print(client.get_and_verify_root())

if __name__ == '__main__':
    main()
