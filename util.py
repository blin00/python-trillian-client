import base64
from hashlib import sha256


def next_smaller_pow2(n):
    """Returns the largest power of 2 that is strictly less than n."""
    return 1 << ((n - 1).bit_length() - 1)

def hash_tree_root(root):
    """Compute the "true" root hash of a tree:
    the hash that's ultimately signed isn't the root_hash field,
    ref:
    https://github.com/google/trillian/blob/master/crypto/data_formats.go
    https://github.com/benlaurie/objecthash/blob/master/objecthash.py
    """
    def hash_str(s):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return sha256(b'u' + s).digest()

    def hash_dict(d):
        final = sha256(b'd')
        entries = (hash_str(k) + hash_str(v) for k, v in d.items())
        for v in sorted(entries):
            final.update(v)
        return final.digest()

    d = {
        'RootHash': base64.b64encode(root.root_hash),
        'TimestampNanos': str(root.timestamp_nanos),
        'TreeSize': str(root.tree_size),
    }
    return hash_dict(d)

def hash_leaf(leaf):
    return sha256(b'\x00' + leaf.leaf_value).digest()

def hash_pair_hashes(a, b):
    return sha256(b'\x01' + a + b).digest()

EMPTY_HASH = sha256(b'').digest()
def hash_leaves(leaves):
    # https://tools.ietf.org/html/rfc6962#section-2.1
    n = len(leaves)
    if n == 0:
        return EMPTY_HASH
    if n == 1:
        return hash_leaf(leaves[0])
    k = next_smaller_pow2(n)
    return hash_pair_hashes(hash_leaves(leaves[:k]), hash_leaves(leaves[k:]))
