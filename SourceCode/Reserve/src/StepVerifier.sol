// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IPoseidon2 {
    function merkleLevel(uint256[4] memory left, uint256[4] memory right)
        external pure returns (uint256[4] memory);
}

/// The step a dispute comes down to.
///
/// Verification is run as a program of typed steps over a memory. The memory
/// is a keccak Merkle tree whose leaves are values; a state is the pair
/// (memory root, step index). The program is fixed by the verifier and the
/// circuit, committed once as a Merkle tree of instructions, and an
/// instruction names its kind, the memory slots it reads and the one slot it
/// writes. Deciding a step is: prove the instruction at that index, prove each
/// value read against the agreed memory root, re-execute, write the result,
/// and return the new root. Neither party chooses what the step does.
///
/// Field elements are Goldilocks, p = 2^64 - 2^32 + 1, so products fit in 128
/// bits and mulmod on 256-bit words is exact. A Poseidon2 digest is four
/// elements packed into one 256-bit leaf, lowest lane in the low bits.
///
/// Every game starts from the empty memory, so nothing about the run's input
/// is the agent's to choose. Input enters only through two step kinds. A
/// LoadBlob step reads one word of the proof from a published blob: the proof
/// is carried as Goldilocks elements, three to a blob field element, and the
/// step opens that field element with the EIP-4844 point-evaluation
/// precompile against the blob's versioned hash. A LoadPublic step reads one
/// of the statement's public values from what the reserve recorded.
contract StepVerifier {
    uint256 internal constant P = 0xFFFFFFFF00000001;
    uint256 internal constant BLS_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    /// A primitive 4096-th root of unity in the BLS12-381 scalar field,
    /// 7^((r-1)/4096). Blob element j is the polynomial's value at
    /// OMEGA^bitrev12(j).
    uint256 internal constant OMEGA =
        0x564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306;
    uint256 internal constant LANES = 3;

    IPoseidon2 public immutable algebraic;

    constructor(address poseidon2) {
        algebraic = IPoseidon2(poseidon2);
    }

    enum Step {
        Fold,      // one FRI fold
        Merkle,    // one level of a keccak path
        Algebraic, // one level of the proof's own Poseidon2 trees
        Linear,    // a linear combination, as constraint batching uses
        Squeeze,   // derive a challenge from transcript state
        Eq,        // 1 if two values agree, else 0; how the verifier records a check
        LoadBlob,  // one proof word from a published blob
        LoadPublic // one public value of the statement
    }

    /// What a load step reads from outside the memory. `pub` is assembled by
    /// the dispute contract from the reserve's record, never by a party.
    /// `kzg` is the claimed field element, the blob's KZG commitment and the
    /// opening proof: 32 + 48 + 48 bytes.
    struct Context {
        uint256[] pub;
        bytes32[] blobs;
        bytes kzg;
    }

    error BadOperand();
    error PathTooLong();
    error BadPath();
    error BadInstruction();
    error BadOpening();

    function inv(uint256 a) public view returns (uint256 r) {
        if (a == 0 || a >= P) revert BadOperand();
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), a, P - 2, P);
        bool ok;
        bytes memory out = new bytes(32);
        assembly {
            ok := staticcall(gas(), 0x05, add(input, 32), 192, add(out, 32), 32)
        }
        require(ok, "modexp");
        r = abi.decode(out, (uint256));
    }

    /// even = (f(x) + f(-x)) / 2, odd = (f(x) - f(-x)) / 2x, out = even + beta * odd.
    function fold(uint256 fx, uint256 fnx, uint256 x, uint256 beta)
        public
        view
        returns (uint256)
    {
        if (fx >= P || fnx >= P || x >= P || beta >= P) revert BadOperand();
        uint256 sum = addmod(fx, fnx, P);
        uint256 diff = addmod(fx, P - fnx, P);
        uint256 even = mulmod(sum, inv(2), P);
        uint256 odd = mulmod(diff, inv(mulmod(2, x, P)), P);
        return addmod(even, mulmod(beta, odd, P), P);
    }

    function pack(uint256[4] memory d) public pure returns (uint256 w) {
        for (uint256 i = 0; i < 4; ++i) {
            if (d[i] >= P) revert BadOperand();
            w |= d[i] << (64 * i);
        }
    }

    function unpack(uint256 w) public pure returns (uint256[4] memory d) {
        for (uint256 i = 0; i < 4; ++i) {
            d[i] = (w >> (64 * i)) & 0xFFFFFFFFFFFFFFFF;
        }
    }

    /// Re-execute one step on the values it read.
    function execute(Step kind, uint256[] memory v) public view returns (uint256) {
        if (kind == Step.Fold) {
            if (v.length != 4) revert BadInstruction();
            return fold(v[0], v[1], v[2], v[3]);
        }
        if (kind == Step.Merkle) {
            if (v.length != 3) revert BadInstruction();
            return v[2] != 0
                ? uint256(keccak256(abi.encodePacked(bytes32(v[0]), bytes32(v[1]))))
                : uint256(keccak256(abi.encodePacked(bytes32(v[1]), bytes32(v[0]))));
        }
        if (kind == Step.Linear) {
            uint256 n = v.length;
            if (n < 2 || n > 65) revert BadInstruction();
            uint256 alpha = v[n - 1];
            uint256 acc;
            for (uint256 i = n - 1; i > 0; --i) {
                if (v[i - 1] >= P) revert BadOperand();
                acc = addmod(mulmod(acc, alpha, P), v[i - 1], P);
            }
            return acc;
        }
        if (kind == Step.Algebraic) {
            if (v.length != 2) revert BadInstruction();
            return pack(algebraic.merkleLevel(unpack(v[0]), unpack(v[1])));
        }
        if (kind == Step.Eq) {
            if (v.length != 2) revert BadInstruction();
            return v[0] == v[1] ? 1 : 0;
        }
        return uint256(keccak256(abi.encodePacked(v))) % P;
    }

    function _modexp(uint256 b, uint256 e, uint256 m) internal view returns (uint256 r) {
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), b, e, m);
        bytes memory out = new bytes(32);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, add(input, 32), 192, add(out, 32), 32)
        }
        require(ok, "modexp");
        r = abi.decode(out, (uint256));
    }

    function _rev12(uint256 x) internal pure returns (uint256 r) {
        for (uint256 i = 0; i < 12; ++i) {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
    }

    /// The point at which blob element j is the polynomial's value.
    function evaluationPoint(uint256 j) public view returns (uint256) {
        if (j >= 4096) revert BadInstruction();
        return _modexp(OMEGA, _rev12(j), BLS_MODULUS);
    }

    /// Lane `lane` of element `j` of blob `b`, proved against the blob's
    /// versioned hash. A lane that is not a Goldilocks element is no word of
    /// an honestly encoded proof, and the step does not decide on it.
    function loadBlob(bytes32 versionedHash, uint256 j, uint256 lane, bytes calldata kzg)
        public
        view
        returns (uint256)
    {
        if (kzg.length != 128 || lane >= LANES) revert BadOpening();
        uint256 y = uint256(bytes32(kzg[0:32]));
        bytes memory input = abi.encodePacked(versionedHash, evaluationPoint(j), kzg);
        (bool ok, bytes memory out) = address(0x0A).staticcall(input);
        if (!ok || out.length != 64) revert BadOpening();
        uint256 w = (y >> (64 * lane)) & 0xFFFFFFFFFFFFFFFF;
        if (w >= P) revert BadOperand();
        return w;
    }

    function rootOf(bytes32 leaf, bytes32[] calldata path, uint256 idx)
        public
        pure
        returns (bytes32 node)
    {
        if (path.length > 64) revert PathTooLong();
        node = leaf;
        for (uint256 i = 0; i < path.length; ++i) {
            node = (idx & 1 == 0)
                ? keccak256(abi.encodePacked(node, path[i]))
                : keccak256(abi.encodePacked(path[i], node));
            idx >>= 1;
        }
    }

    function instructionLeaf(Step kind, uint256[] memory reads, uint256 write)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(uint8(kind), reads, write));
    }

    /// Everything one step needs, with its proofs. `paths` holds the program
    /// path, then one path per read, then the write path, each `depth` long
    /// except the program path, which is `programDepth` long.
    struct StepInput {
        Step kind;
        uint256[] reads;
        uint256 write;
        uint256[] values;
        uint256 oldValue;
        bytes32[] paths;
    }

    /// The memory root after the step at `index`, from the agreed root before
    /// it. Reverts on any proof that does not check, so a party submitting
    /// false operands gains nothing: the step is decided only on true ones.
    /// For the two load kinds, `reads` holds the instruction's immediates
    /// (blob, element, lane; or the public value's position) and no memory is
    /// read.
    /// Where a step sits: the program it belongs to, its index, and the
    /// agreed memory before it.
    struct Frame {
        bytes32 programRoot;
        uint256 programDepth;
        uint256 index;
        bytes32 memRoot;
        uint256 depth;
    }

    function transition(Frame calldata f, StepInput calldata s, Context calldata c)
        external
        view
        returns (bytes32)
    {
        uint256 programDepth = f.programDepth;
        uint256 depth = f.depth;
        bytes32 memRoot = f.memRoot;
        bool load = s.kind == Step.LoadBlob || s.kind == Step.LoadPublic;
        uint256 n = load ? 0 : s.reads.length;
        if (s.values.length != n || s.paths.length != programDepth + (n + 1) * depth) {
            revert BadPath();
        }
        if (rootOf(instructionLeaf(s.kind, s.reads, s.write), s.paths[0:programDepth], f.index)
            != f.programRoot) revert BadInstruction();

        uint256 at = programDepth;
        for (uint256 i = 0; i < n; ++i) {
            if (rootOf(bytes32(s.values[i]), s.paths[at:at + depth], s.reads[i]) != memRoot) {
                revert BadPath();
            }
            at += depth;
        }
        bytes32[] calldata wp = s.paths[at:at + depth];
        if (rootOf(bytes32(s.oldValue), wp, s.write) != memRoot) revert BadPath();

        uint256 result;
        if (s.kind == Step.LoadBlob) {
            if (s.reads.length != 3 || s.reads[0] >= c.blobs.length) revert BadInstruction();
            result = loadBlob(c.blobs[s.reads[0]], s.reads[1], s.reads[2], c.kzg);
        } else if (s.kind == Step.LoadPublic) {
            if (s.reads.length != 1 || s.reads[0] >= c.pub.length) revert BadInstruction();
            result = c.pub[s.reads[0]];
            if (result >= P) revert BadOperand();
        } else {
            result = execute(s.kind, s.values);
        }
        return rootOf(bytes32(result), wp, s.write);
    }
}
