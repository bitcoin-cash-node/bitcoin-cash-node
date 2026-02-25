#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2019 The Bitcoin Core developers
# Copyright (c) 2022-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin test framework primitive and message structures

CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives

msg_block, msg_tx, msg_headers, etc.:
    data structures that represent network messages

ser_*, deser_*: functions that handle serialization/deserialization.

Classes use __slots__ to ensure extraneous attributes aren't accidentally added
by tests, compromising their intended effect.
"""
from codecs import encode
import copy
from enum import IntEnum
import hashlib
from io import BytesIO
import random
import socket
import struct
import time
from typing import Optional, Tuple

from test_framework.siphash import siphash256
from test_framework.util import hex_str_to_bytes

MIN_VERSION_SUPPORTED = 60001
# past bip-31 for ping/pong, post sendaddrv2
MY_VERSION = 70016
MY_SUBVERSION = b"/python-p2p-tester:0.0.3/"
# from version 70001 onwards, fRelay should be appended to version
# messages (BIP37)
MY_RELAY = 1

MAX_INV_SZ = 50000
MAX_LOCATOR_SZ = 101
MAX_BLOCK_BASE_SIZE = 1000000

# 1 BCH in satoshis
COIN = 100000000

MAX_PROTOCOL_MESSAGE_LENGTH = 2 * 1024 * 1024  # Maximum length of incoming protocol messages
MAX_HEADERS_RESULTS = 2000  # Number of headers sent in one getheaders result
MAX_INV_SIZE = 50000  # Maximum number of entries in an 'inv' protocol message

# Known network service flags; not all of these are used by BCHN
NODE_NETWORK = (1 << 0)
NODE_GETUTXO = (1 << 1)
NODE_BLOOM = (1 << 2)
NODE_WITNESS = (1 << 3)
NODE_XTHIN = (1 << 4)
NODE_BITCOIN_CASH = (1 << 5)
NODE_GRAPHENE = (1 << 6)
NODE_CF = (1 << 8)
NODE_NETWORK_LIMITED = (1 << 10)
NODE_EXTVERSION = (1 << 11)

MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4
MSG_TYPE_MASK = 0xffffffff >> 2
MSG_DSPROOF = 0x94a0  # Temporary type id

# Serialization/deserialization tools


def sha256(s):
    return hashlib.new('sha256', s).digest()


def ripemd160(s):
    return hashlib.new('ripemd160', s).digest()


def hash256(s):
    return sha256(sha256(s))


def ser_compact_size(size):
    r = b""
    if size < 253:
        r = struct.pack("B", size)
    elif size < 0x10000:
        r = struct.pack("<BH", 253, size)
    elif size < 0x100000000:
        r = struct.pack("<BI", 254, size)
    else:
        r = struct.pack("<BQ", 255, size)
    return r


def deser_compact_size(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)


def ser_string(s):
    return ser_compact_size(len(s)) + s


def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s):
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


# deser_function_name: Allow for an alternate deserialization function on the
# entries in the vector.
def deser_vector(f, c, deser_function_name=None):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = c()
        if deser_function_name:
            getattr(t, deser_function_name)(f)
        else:
            t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector.
def ser_vector(v, ser_function_name=None):
    r = ser_compact_size(len(v))
    for i in v:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(v):
    r = ser_compact_size(len(v))
    for i in v:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(v):
    r = ser_compact_size(len(v))
    for sv in v:
        r += ser_string(sv)
    return r


class CompactSize(int):
    def serialize(self):
        assert self >= 0
        if self < 253:
            return struct.pack("<B", self)
        elif self < 2**16:
            return struct.pack("<B", 253) + struct.pack("<H", self)
        elif self < 2**32:
            return struct.pack("<B", 254) + struct.pack("<I", self)
        elif self < 2**64:
            return struct.pack("<B", 255) + struct.pack("<Q", self)

    def deserialize(self, f):
        self = struct.unpack("<B", f.read(1))[0]
        if self == 253:
            self = struct.unpack("<H", f.read(2))[0]
        elif self == 254:
            self = struct.unpack("<I", f.read(4))[0]
        elif self == 255:
            self = struct.unpack("<Q", f.read(8))[0]
        return self


# Deserialize from a hex string representation (eg from RPC)


def FromHex(obj, hex_string):
    obj.deserialize(BytesIO(hex_str_to_bytes(hex_string)))
    return obj

# Convert a binary-serializable object to hex (eg for submission via RPC)


def ToHex(obj):
    return obj.serialize().hex()

# Objects that map to bitcoind objects, which can be serialized/deserialized


class CAddress:
    __slots__ = ("net", "ip", "nServices", "port", "time")

    # see https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
    NET_IPV4 = 1

    ADDRV2_NET_NAME = {
        NET_IPV4: "IPv4"
    }

    ADDRV2_ADDRESS_LENGTH = {
        NET_IPV4: 4
    }

    def __init__(self):
        self.time = 0
        self.nServices = 1
        self.net = self.NET_IPV4
        self.ip = "0.0.0.0"
        self.port = 0

    def deserialize(self, f, *, with_time=True):
        """Deserialize from addrv1 format (pre-BIP155)"""
        if with_time:
            # VERSION messages serialize CAddress objects without time
            self.time = struct.unpack("<I", f.read(4))[0]
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        # We only support IPv4 which means skip 12 bytes and read the next 4 as IPv4 address.
        f.read(12)
        self.net = self.NET_IPV4
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = struct.unpack(">H", f.read(2))[0]

    def serialize(self, *, with_time=True):
        """Serialize in addrv1 format (pre-BIP155)"""
        assert self.net == self.NET_IPV4
        r = b""
        if with_time:
            # VERSION messages serialize CAddress objects without time
            r += struct.pack("<I", self.time)
        r += struct.pack("<Q", self.nServices)
        r += b"\x00" * 10 + b"\xff" * 2
        r += socket.inet_aton(self.ip)
        r += struct.pack(">H", self.port)
        return r

    def deserialize_v2(self, f):
        """Deserialize from addrv2 format (BIP155)"""
        self.time = struct.unpack("<I", f.read(4))[0]

        self.nServices = deser_compact_size(f)

        self.net = struct.unpack("B", f.read(1))[0]
        assert self.net == self.NET_IPV4

        address_length = deser_compact_size(f)
        assert address_length == self.ADDRV2_ADDRESS_LENGTH[self.net]

        self.ip = socket.inet_ntoa(f.read(4))

        self.port = struct.unpack(">H", f.read(2))[0]

    def serialize_v2(self):
        """Serialize in addrv2 format (BIP155)"""
        assert self.net == self.NET_IPV4
        r = b""
        r += struct.pack("<I", self.time)
        r += ser_compact_size(self.nServices)
        r += struct.pack("B", self.net)
        r += ser_compact_size(self.ADDRV2_ADDRESS_LENGTH[self.net])
        r += socket.inet_aton(self.ip)
        r += struct.pack(">H", self.port)
        return r

    def __repr__(self):
        return ("CAddress(nServices=%i net=%s addr=%s port=%i)"
                % (self.nServices, self.ADDRV2_NET_NAME[self.net], self.ip, self.port))


class CInv:
    __slots__ = ("hash", "type")

    typemap = {
        0: "Error",
        MSG_TX: "TX",
        MSG_BLOCK: "Block",
        MSG_FILTERED_BLOCK: "filtered Block",
        MSG_CMPCT_BLOCK: "CompactBlock",
        0x94a0: "DoubleSpendProofbeta",
    }

    def __init__(self, t=0, h=0):
        self.type = t
        self.hash = h

    def deserialize(self, f):
        self.type = struct.unpack("<i", f.read(4))[0]
        self.hash = deser_uint256(f)

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.type)
        r += ser_uint256(self.hash)
        return r

    def __repr__(self):
        return "CInv(type={} hash={:064x})".format(
            self.typemap[self.type], self.hash)


class CBlockLocator:
    __slots__ = ("nVersion", "vHave")

    def __init__(self):
        self.nVersion = MY_VERSION
        self.vHave = []

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vHave = deser_uint256_vector(f)

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_uint256_vector(self.vHave)
        return r

    def __repr__(self):
        return "CBlockLocator(nVersion={} vHave={})".format(
            self.nVersion, repr(self.vHave))


class COutPoint:
    __slots__ = ("hash", "n")

    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = struct.unpack("<I", f.read(4))[0]

    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        r += struct.pack("<I", self.n)
        return r

    def __repr__(self):
        return "COutPoint(hash={:064x} n={})".format(self.hash, self.n)


class CTxIn:
    __slots__ = ("nSequence", "prevout", "scriptSig")

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]

    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += struct.pack("<I", self.nSequence)
        return r

    def __repr__(self):
        return "CTxIn(prevout={} scriptSig={} nSequence={})".format(
            repr(self.prevout), self.scriptSig.hex(), self.nSequence)


class TokenStructure(IntEnum):
    HasAmount = 0x10
    HasNFT = 0x20
    HasCommitmentLength = 0x40


class TokenCapability(IntEnum):
    NoCapability = 0x00
    Mutable = 0x01
    Minting = 0x02


class TokenOutputData:
    __slots__ = ("id", "bitfield", "amount", "commitment")

    def __init__(self, id: int = 0, amount: int = 1, commitment: bytes = b'',
                 bitfield: int = TokenStructure.HasAmount):
        self.id = id
        self.amount = amount
        self.commitment = commitment
        self.bitfield = bitfield

    @property
    def id_hex(self) -> str:
        return ser_uint256(self.id)[::-1].hex()

    @id_hex.setter
    def id_hex(self, hex: str):
        b = bytes.fromhex(hex)
        assert len(b) == 32
        self.id = uint256_from_str(b[::-1])

    def deserialize(self, f):
        self.id = deser_uint256(f)
        self.bitfield = struct.unpack("<B", f.read(1))[0]
        if self.HasCommitmentLength():
            self.commitment = deser_string(f)
        else:
            self.commitment = b''
        if self.HasAmount():
            self.amount = deser_compact_size(f)
        else:
            self.amount = 0

    def serialize(self) -> bytes:
        r = bytearray()
        r += ser_uint256(self.id)
        r += struct.pack("B", self.bitfield)
        if self.HasCommitmentLength():
            r += ser_string(self.commitment)
        if self.HasAmount():
            r += ser_compact_size(self.amount)
        return bytes(r)

    def GetCapability(self) -> int:
        return self.bitfield & 0x0f

    def HasCommitmentLength(self) -> bool:
        return bool(self.bitfield & TokenStructure.HasCommitmentLength)

    def HasAmount(self) -> bool:
        return bool(self.bitfield & TokenStructure.HasAmount)

    def HasNFT(self) -> bool:
        return bool(self.bitfield & TokenStructure.HasNFT)

    def IsMintingNFT(self) -> bool:
        return self.HasNFT() and self.GetCapability() == TokenCapability.Minting

    def IsMutableNFT(self) -> bool:
        return self.HasNFT() and self.GetCapability() == TokenCapability.Mutable

    def IsImmutableNFT(self) -> bool:
        return self.HasNFT() and self.GetCapability() == TokenCapability.NoCapability

    def IsValidBitfield(self) -> bool:
        s = self.bitfield & 0xf0
        if s >= 0x80 or s == 0x00:
            return False
        if self.bitfield & 0x0f > 2:
            return False
        if not self.HasNFT() and not self.HasAmount():
            return False
        if not self.HasNFT() and (self.bitfield & 0x0f) != 0:
            return False
        if not self.HasNFT() and self.HasCommitmentLength():
            return False
        return True

    def __repr__(self) -> str:
        return f"TokenOutputData(id={self.id_hex} bitfield={self.bitfield:02x} amount={self.amount} " \
               f"commitment={self.commitment[:40].hex()})"


class token:
    """Emulate the C++ 'token' namespace"""
    PREFIX_BYTE = bytes([0xef])
    Structure = TokenStructure
    Capability = TokenCapability
    OutputData = TokenOutputData

    @classmethod
    def wrap_spk(cls, token_data: Optional[TokenOutputData], script_pub_key: bytes) -> bytes:
        if not token_data:
            return script_pub_key
        buf = bytearray()
        buf += cls.PREFIX_BYTE
        buf += token_data.serialize()
        buf += script_pub_key
        return bytes(buf)

    @classmethod
    def unwrap_spk(cls, wrapped_spk: bytes) -> Tuple[Optional[TokenOutputData], bytes]:
        if not wrapped_spk or wrapped_spk[0] != cls.PREFIX_BYTE[0]:
            return None, wrapped_spk
        token_data = TokenOutputData()
        f = BytesIO(wrapped_spk)
        pfx = f.read(1)  # consume prefix byte
        assert pfx == cls.PREFIX_BYTE
        token_data.deserialize(f)  # unserialize token_data from buffer after prefix_byte
        if (not token_data.IsValidBitfield() or (token_data.HasAmount() and not token_data.amount)
                or (token_data.HasCommitmentLength() and not token_data.commitment)):
            # Bad bitfield or 0 serialized amount or empty serialized commitment is a deserialization error,
            # just return the entire buffer as spk
            return None, wrapped_spk
        spk = wrapped_spk[f.tell():]  # leftover bytes go to real spk
        return token_data, spk  # Parsed ok


class CTxOut:
    __slots__ = ("nValue", "scriptPubKey", "tokenData")

    def __init__(self, nValue=0, scriptPubKey=b"", tokenData=None):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey
        self.tokenData = tokenData

    def deserialize(self, f):
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.tokenData, self.scriptPubKey = token.unwrap_spk(deser_string(f))

    def serialize(self):
        r = bytearray()
        r += struct.pack("<q", self.nValue)
        r += ser_string(token.wrap_spk(self.tokenData, self.scriptPubKey))
        return bytes(r)

    def __repr__(self):
        return "CTxOut(nValue={}.{:08d} scriptPubKey={} tokenData={})".format(
            self.nValue // COIN, self.nValue % COIN, self.scriptPubKey.hex(), repr(self.tokenData))


class CTransaction:
    __slots__ = ("hash", "nLockTime", "nVersion", "sha256", "vin", "vout")

    def __init__(self, tx=None):
        if tx is None:
            self.nVersion = 1
            self.vin = []
            self.vout = []
            self.nLockTime = 0
            self.sha256 = None
            self.hash = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    def billable_size(self):
        """
        Returns the size used for billing the against the transaction
        """
        return len(self.serialize())

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        return r

    # Recalculate the txid
    def rehash(self):
        self.sha256 = None
        self.calc_sha256()
        return self.hash

    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self):
        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize()))
        self.hash = encode(
            hash256(self.serialize())[::-1], 'hex_codec').decode('ascii')

    def get_id(self):
        # For now, just forward the hash.
        self.calc_sha256()
        return self.hash

    def is_valid(self):
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    def __repr__(self):
        return "CTransaction(nVersion={} vin={} vout={} nLockTime={})".format(
            self.nVersion, repr(self.vin), repr(self.vout), self.nLockTime)


class CBlockHeader:
    __slots__ = ("hash", "hashMerkleRoot", "hashPrevBlock", "nBits", "nNonce",
                 "nTime", "nVersion", "sha256")

    def __init__(self, header=None):
        if header is None:
            self.set_null()
        else:
            self.nVersion = header.nVersion
            self.hashPrevBlock = header.hashPrevBlock
            self.hashMerkleRoot = header.hashMerkleRoot
            self.nTime = header.nTime
            self.nBits = header.nBits
            self.nNonce = header.nNonce
            self.sha256 = header.sha256
            self.hash = header.hash
            self.calc_sha256()

    def set_null(self):
        self.nVersion = 1
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        self.sha256 = None
        self.hash = None

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.nTime = struct.unpack("<I", f.read(4))[0]
        self.nBits = struct.unpack("<I", f.read(4))[0]
        self.nNonce = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_uint256(self.hashPrevBlock)
        r += ser_uint256(self.hashMerkleRoot)
        r += struct.pack("<I", self.nTime)
        r += struct.pack("<I", self.nBits)
        r += struct.pack("<I", self.nNonce)
        return r

    def calc_sha256(self):
        if self.sha256 is None:
            r = b""
            r += struct.pack("<i", self.nVersion)
            r += ser_uint256(self.hashPrevBlock)
            r += ser_uint256(self.hashMerkleRoot)
            r += struct.pack("<I", self.nTime)
            r += struct.pack("<I", self.nBits)
            r += struct.pack("<I", self.nNonce)
            self.sha256 = uint256_from_str(hash256(r))
            self.hash = encode(hash256(r)[::-1], 'hex_codec').decode('ascii')

    def rehash(self):
        self.sha256 = None
        self.calc_sha256()
        return self.sha256

    def __repr__(self):
        return "CBlockHeader(nVersion={} hashPrevBlock={:064x} hashMerkleRoot={:064x} nTime={} nBits={:08x} nNonce={:08x})".format(
            self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
            self.nTime, self.nBits, self.nNonce)


class CBlock(CBlockHeader):
    __slots__ = ("vtx",)

    def __init__(self, header=None):
        super(CBlock, self).__init__(header)
        self.vtx = []

    def deserialize(self, f):
        super(CBlock, self).deserialize(f)
        self.vtx = deser_vector(f, CTransaction)

    def serialize(self):
        r = b""
        r += super(CBlock, self).serialize()
        r += ser_vector(self.vtx)
        return r

    # Calculate the merkle root given a vector of transaction hashes
    def get_merkle_root(self, hashes):
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i + 1, len(hashes) - 1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        if hashes:
            return uint256_from_str(hashes[0])
        return 0

    def calc_merkle_root(self):
        hashes = []
        for tx in self.vtx:
            tx.calc_sha256()
            hashes.append(ser_uint256(tx.sha256))
        return self.get_merkle_root(hashes)

    def is_valid(self):
        self.calc_sha256()
        target = uint256_from_compact(self.nBits)
        if self.sha256 > target:
            return False
        for tx in self.vtx:
            if not tx.is_valid():
                return False
        if self.calc_merkle_root() != self.hashMerkleRoot:
            return False
        return True

    def solve(self):
        self.rehash()
        target = uint256_from_compact(self.nBits)
        while self.sha256 > target:
            self.nNonce += 1
            self.rehash()

    def __repr__(self):
        return "CBlock(nVersion={} hashPrevBlock={:064x} hashMerkleRoot={:064x} nTime={} nBits={:08x} nNonce={:08x} vtx={})".format(
            self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
            self.nTime, self.nBits, self.nNonce, repr(self.vtx))


class CDSProof:
    __slots__ = ("prevTxId",
                 "prevOutIndex",
                 "spender1",
                 "spender2")

    def __init__(self, dsproof=None):
        if dsproof is None:
            self.prevTxId = None
            self.prevOutIndex = 0
            self.spender1 = CDSProofSpender()
            self.spender2 = CDSProofSpender()
        else:
            self.prevTxId = dsproof.prevTxId
            self.prevOutIndex = dsproof.prevOutIndex
            self.spender1 = dsproof.spender1
            self.spender2 = dsproof.spender2

    def deserialize(self, f):
        self.prevTxId = deser_uint256(f)
        self.prevOutIndex = struct.unpack("<i", f.read(4))[0]
        self.spender1 = CDSProofSpender()
        self.spender1.deserialize(f)
        self.spender2 = CDSProofSpender()
        self.spender2.deserialize(f)

    def serialize(self):
        r = self.getPrevOutput()
        r += self.spender1.serialize()
        r += self.spender2.serialize()
        return r

    def getPrevOutput(self):
        r = b""
        r += ser_uint256(self.prevTxId)
        r += struct.pack("<I", self.prevOutIndex)
        return r

    def __repr__(self):
        return "CDSProof(prevTxId={:064x} prevOutIndex={}\nspender1={}\nspender2={})".format(
            self.prevTxId, self.prevOutIndex, self.spender1, self.spender2)


class CDSProofSpender:

    __slots__ = ("txVersion",
                 "outSequence",
                 "lockTime",
                 "hashPrevOutputs",
                 "hashSequence",
                 "hashOutputs",
                 "pushData")

    def __init__(self, spender=None):
        if spender is None:
            self.txVersion = 0
            self.outSequence = 0
            self.lockTime = 0
            self.hashPrevOutputs = None
            self.hashSequence = None
            self.hashOutputs = None
            self.pushData = []
        else:
            self.txVersion = spender.txVersion
            self.outSequence = spender.outSequence
            self.lockTime = spender.lockTime
            self.hashPrevOutputs = spender.hashPrevOutputs
            self.hashSequence = spender.hashSequence
            self.hashOutputs = spender.hashOutputs
            self.pushData = spender.pushData

    def deserialize(self, f):
        self.txVersion = struct.unpack("<i", f.read(4))[0]
        self.outSequence = struct.unpack("<I", f.read(4))[0]
        self.lockTime = struct.unpack("<I", f.read(4))[0]
        self.hashPrevOutputs = deser_uint256(f)
        self.hashSequence = deser_uint256(f)
        self.hashOutputs = deser_uint256(f)
        self.pushData = deser_string_vector(f)

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.txVersion)
        r += struct.pack("<I", self.outSequence)
        r += struct.pack("<I", self.lockTime)
        r += ser_uint256(self.hashPrevOutputs)
        r += ser_uint256(self.hashSequence)
        r += ser_uint256(self.hashOutputs)
        r += ser_string_vector(self.pushData)
        return r

    def pushDataToHex(self, data):
        return "[" + ",".join(map(bytes.hex, data)) + "]"

    def __repr__(self):
        return "spender1txVersion={} spender1outSequence={} spender1lockTime={} spender1hashPrevOutputs={:064x} spender1hashSequence={:064x} spender1hashOutputs={:064x} spender1pushData={}".format(
            self.txVersion, self.outSequence, self.lockTime, self.hashPrevOutputs, self.hashSequence, self.hashOutputs, self.pushDataToHex(
                self.pushData)
        )


class PrefilledTransaction:
    __slots__ = ("index", "tx")

    def __init__(self, index=0, tx=None):
        self.index = index
        self.tx = tx

    def deserialize(self, f):
        self.index = deser_compact_size(f)
        self.tx = CTransaction()
        self.tx.deserialize(f)

    def serialize(self):
        r = b""
        r += ser_compact_size(self.index)
        r += self.tx.serialize()
        return r

    def __repr__(self):
        return "PrefilledTransaction(index={}, tx={})".format(
            self.index, repr(self.tx))


# This is what we send on the wire, in a cmpctblock message.
class P2PHeaderAndShortIDs:
    __slots__ = ("header", "nonce", "prefilled_txn", "prefilled_txn_length",
                 "shortids", "shortids_length")

    def __init__(self):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids_length = 0
        self.shortids = []
        self.prefilled_txn_length = 0
        self.prefilled_txn = []

    def deserialize(self, f):
        self.header.deserialize(f)
        self.nonce = struct.unpack("<Q", f.read(8))[0]
        self.shortids_length = deser_compact_size(f)
        for i in range(self.shortids_length):
            # shortids are defined to be 6 bytes in the spec, so append
            # two zero bytes and read it in as an 8-byte number
            self.shortids.append(
                struct.unpack("<Q", f.read(6) + b'\x00\x00')[0])
        self.prefilled_txn = deser_vector(f, PrefilledTransaction)
        self.prefilled_txn_length = len(self.prefilled_txn)

    def serialize(self):
        r = b""
        r += self.header.serialize()
        r += struct.pack("<Q", self.nonce)
        r += ser_compact_size(self.shortids_length)
        for x in self.shortids:
            # We only want the first 6 bytes
            r += struct.pack("<Q", x)[0:6]
        r += ser_vector(self.prefilled_txn)
        return r

    def __repr__(self):
        return "P2PHeaderAndShortIDs(header={}, nonce={}, shortids_length={}, shortids={}, prefilled_txn_length={}, prefilledtxn={}".format(
            repr(self.header), self.nonce, self.shortids_length,
            repr(self.shortids), self.prefilled_txn_length,
            repr(self.prefilled_txn))

# Calculate the BIP 152-compact blocks shortid for a given transaction hash


def calculate_shortid(k0, k1, tx_hash):
    expected_shortid = siphash256(k0, k1, tx_hash)
    expected_shortid &= 0x0000ffffffffffff
    return expected_shortid


# This version gets rid of the array lengths, and reinterprets the differential
# encoding into indices that can be used for lookup.
class HeaderAndShortIDs:
    __slots__ = ("header", "nonce", "prefilled_txn", "shortids")

    def __init__(self, p2pheaders_and_shortids=None):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids = []
        self.prefilled_txn = []

        if p2pheaders_and_shortids is not None:
            self.header = p2pheaders_and_shortids.header
            self.nonce = p2pheaders_and_shortids.nonce
            self.shortids = p2pheaders_and_shortids.shortids
            last_index = -1
            for x in p2pheaders_and_shortids.prefilled_txn:
                self.prefilled_txn.append(
                    PrefilledTransaction(x.index + last_index + 1, x.tx))
                last_index = self.prefilled_txn[-1].index

    def to_p2p(self):
        ret = P2PHeaderAndShortIDs()
        ret.header = self.header
        ret.nonce = self.nonce
        ret.shortids_length = len(self.shortids)
        ret.shortids = self.shortids
        ret.prefilled_txn_length = len(self.prefilled_txn)
        ret.prefilled_txn = []
        last_index = -1
        for x in self.prefilled_txn:
            ret.prefilled_txn.append(
                PrefilledTransaction(x.index - last_index - 1, x.tx))
            last_index = x.index
        return ret

    def get_siphash_keys(self):
        header_nonce = self.header.serialize()
        header_nonce += struct.pack("<Q", self.nonce)
        hash_header_nonce_as_str = sha256(header_nonce)
        key0 = struct.unpack("<Q", hash_header_nonce_as_str[0:8])[0]
        key1 = struct.unpack("<Q", hash_header_nonce_as_str[8:16])[0]
        return [key0, key1]

    # Version 2 compact blocks use wtxid in shortids (rather than txid)
    def initialize_from_block(self, block, nonce=0, prefill_list=None):
        if prefill_list is None:
            prefill_list = [0]
        self.header = CBlockHeader(block)
        self.nonce = nonce
        self.prefilled_txn = [PrefilledTransaction(i, block.vtx[i])
                              for i in prefill_list]
        self.shortids = []
        [k0, k1] = self.get_siphash_keys()
        for i in range(len(block.vtx)):
            if i not in prefill_list:
                tx_hash = block.vtx[i].sha256
                self.shortids.append(calculate_shortid(k0, k1, tx_hash))

    def __repr__(self):
        return "HeaderAndShortIDs(header={}, nonce={}, shortids={}, prefilledtxn={}".format(
            repr(self.header), self.nonce, repr(self.shortids),
            repr(self.prefilled_txn))


class BlockTransactionsRequest:
    __slots__ = ("blockhash", "indexes")

    def __init__(self, blockhash=0, indexes=None):
        self.blockhash = blockhash
        self.indexes = indexes if indexes is not None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        indexes_length = deser_compact_size(f)
        for i in range(indexes_length):
            self.indexes.append(deser_compact_size(f))

    def serialize(self):
        r = b""
        r += ser_uint256(self.blockhash)
        r += ser_compact_size(len(self.indexes))
        for x in self.indexes:
            r += ser_compact_size(x)
        return r

    # helper to set the differentially encoded indexes from absolute ones
    def from_absolute(self, absolute_indexes):
        self.indexes = []
        last_index = -1
        for x in absolute_indexes:
            self.indexes.append(x - last_index - 1)
            last_index = x

    def to_absolute(self):
        absolute_indexes = []
        last_index = -1
        for x in self.indexes:
            absolute_indexes.append(x + last_index + 1)
            last_index = absolute_indexes[-1]
        return absolute_indexes

    def __repr__(self):
        return "BlockTransactionsRequest(hash={:064x} indexes={})".format(
            self.blockhash, repr(self.indexes))


class BlockTransactions:
    __slots__ = ("blockhash", "transactions")

    def __init__(self, blockhash=0, transactions=None):
        self.blockhash = blockhash
        self.transactions = transactions if transactions is not None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        self.transactions = deser_vector(f, CTransaction)

    def serialize(self):
        r = b""
        r += ser_uint256(self.blockhash)
        r += ser_vector(self.transactions)
        return r

    def __repr__(self):
        return "BlockTransactions(hash={:064x} transactions={})".format(
            self.blockhash, repr(self.transactions))


class CPartialMerkleTree:
    __slots__ = ("fBad", "nTransactions", "vBits", "vHash")

    def __init__(self):
        self.nTransactions = 0
        self.vHash = []
        self.vBits = []
        self.fBad = False

    def deserialize(self, f):
        self.nTransactions = struct.unpack("<i", f.read(4))[0]
        self.vHash = deser_uint256_vector(f)
        vBytes = deser_string(f)
        self.vBits = []
        for i in range(len(vBytes) * 8):
            self.vBits.append(vBytes[i // 8] & (1 << (i % 8)) != 0)

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.nTransactions)
        r += ser_uint256_vector(self.vHash)
        vBytesArray = bytearray([0x00] * ((len(self.vBits) + 7) // 8))
        for i in range(len(self.vBits)):
            vBytesArray[i // 8] |= self.vBits[i] << (i % 8)
        r += ser_string(bytes(vBytesArray))
        return r

    def __repr__(self):
        return "CPartialMerkleTree(nTransactions={}, vHash={}, vBits={})".format(
            self.nTransactions, repr(self.vHash), repr(self.vBits))


class CMerkleBlock:
    __slots__ = ("header", "txn")

    def __init__(self):
        self.header = CBlockHeader()
        self.txn = CPartialMerkleTree()

    def deserialize(self, f):
        self.header.deserialize(f)
        self.txn.deserialize(f)

    def serialize(self):
        r = b""
        r += self.header.serialize()
        r += self.txn.serialize()
        return r

    def __repr__(self):
        return "CMerkleBlock(header={}, txn={})".format(
            repr(self.header), repr(self.txn))


# Objects that correspond to messages on the wire


class msg_version:
    __slots__ = ("addrFrom", "addrTo", "nNonce", "nRelay", "nServices",
                 "nStartingHeight", "nTime", "nVersion", "strSubVer")
    msgtype = b"version"

    def __init__(self):
        self.nVersion = MY_VERSION
        self.nServices = 1
        self.nTime = int(time.time())
        self.addrTo = CAddress()
        self.addrFrom = CAddress()
        self.nNonce = random.getrandbits(64)
        self.strSubVer = MY_SUBVERSION
        self.nStartingHeight = -1
        self.nRelay = MY_RELAY

    def deserialize(self, f):
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.nTime = struct.unpack("<q", f.read(8))[0]
        self.addrTo = CAddress()
        self.addrTo.deserialize(f, with_time=False)

        self.addrFrom = CAddress()
        self.addrFrom.deserialize(f, with_time=False)
        self.nNonce = struct.unpack("<Q", f.read(8))[0]
        self.strSubVer = deser_string(f)

        self.nStartingHeight = struct.unpack("<i", f.read(4))[0]

        if self.nVersion >= 70001:
            # Relay field is optional for version 70001 onwards
            try:
                self.nRelay = struct.unpack("<b", f.read(1))[0]
            except Exception:
                self.nRelay = 0
        else:
            self.nRelay = 0

    def serialize(self):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += struct.pack("<Q", self.nServices)
        r += struct.pack("<q", self.nTime)
        r += self.addrTo.serialize(with_time=False)
        r += self.addrFrom.serialize(with_time=False)
        r += struct.pack("<Q", self.nNonce)
        r += ser_string(self.strSubVer)
        r += struct.pack("<i", self.nStartingHeight)
        r += struct.pack("<b", self.nRelay)
        return r

    def __repr__(self):
        return 'msg_version(nVersion={} nServices={} nTime={} addrTo={} addrFrom={} nNonce=0x{:016X} strSubVer={} nStartingHeight={} nRelay={})'.format(
            self.nVersion, self.nServices, self.nTime,
            repr(self.addrTo), repr(self.addrFrom), self.nNonce,
            self.strSubVer, self.nStartingHeight, self.nRelay)


class msg_extversion(object):
    msgtype = b"extversion"

    def __init__(self, xver=None):
        if xver is None:
            xver = {}
        self.xver = xver

    def deserialize(self, f):
        map_size = CompactSize().deserialize(f)
        self.xver = {}
        for i in range(map_size):
            key = CompactSize().deserialize(f)
            val_size = CompactSize().deserialize(f)
            value = f.read(val_size)
            self.xver[key] = value

    def serialize(self):
        res = CompactSize(len(self.xver)).serialize()
        for k, v in self.xver.items():
            res += CompactSize(k).serialize()
            if isinstance(v, int):
                # serialize integers in compact format inside the vector
                v = CompactSize(v).serialize()
            res += CompactSize(len(v)).serialize()
            res += v
        return res

    def __repr__(self):
        return "msg_extversion({})".format(repr(self.xver))


class msg_verack:
    __slots__ = ()
    msgtype = b"verack"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_verack()"


class msg_addr:
    __slots__ = ("addrs",)
    msgtype = b"addr"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress)

    def serialize(self):
        return ser_vector(self.addrs)

    def __repr__(self):
        return "msg_addr(addrs={})".format(repr(self.addrs))


class msg_addrv2:
    __slots__ = ("addrs",)
    msgtype = b"addrv2"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress, "deserialize_v2")

    def serialize(self):
        return ser_vector(self.addrs, "serialize_v2")

    def __repr__(self):
        return "msg_addrv2(addrs={})".format(repr(self.addrs))


class msg_sendaddrv2:
    __slots__ = ()
    msgtype = b"sendaddrv2"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_sendaddrv2()"


class msg_inv:
    __slots__ = ("inv",)
    msgtype = b"inv"

    def __init__(self, inv=None):
        if inv is None:
            self.inv = []
        else:
            self.inv = inv

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_inv(inv={})".format(repr(self.inv))


class msg_getdata:
    __slots__ = ("inv",)
    msgtype = b"getdata"

    def __init__(self, inv=None):
        self.inv = inv if inv is not None else []

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_getdata(inv={})".format(repr(self.inv))


class msg_getblocks:
    __slots__ = ("locator", "hashstop")
    msgtype = b"getblocks"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getblocks(locator={} hashstop={:064x})".format(
            repr(self.locator), self.hashstop)


class msg_tx:
    __slots__ = ("tx",)
    msgtype = b"tx"

    def __init__(self, tx=CTransaction()):
        self.tx = tx

    def deserialize(self, f):
        self.tx.deserialize(f)

    def serialize(self):
        return self.tx.serialize()

    def __repr__(self):
        return "msg_tx(tx={})".format(repr(self.tx))


class msg_block:
    __slots__ = ("block",)
    msgtype = b"block"

    def __init__(self, block=None):
        if block is None:
            self.block = CBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)

    def serialize(self):
        return self.block.serialize()

    def __repr__(self):
        return "msg_block(block={})".format(repr(self.block))


class msg_dsproof:
    __slots__ = ("dsproof",)
    msgtype = b"dsproof-beta"

    def __init__(self, dsproof=None):
        if dsproof is None:
            self.dsproof = CDSProof()
        else:
            self.dsproof = dsproof

    def deserialize(self, f):
        self.dsproof.deserialize(f)

    def serialize(self):
        return self.dsproof.serialize()

    def __repr__(self):
        return "msg_dsproof(dsproof-beta={})".format(repr(self.dsproof))


# for cases where a user needs tighter control over what is sent over the wire
# note that the user must supply the name of the msgtype, and the data


class msg_generic:
    __slots__ = ("msgtype", "data")

    def __init__(self, msgtype, data=None):
        self.msgtype = msgtype
        self.data = data

    def serialize(self):
        return self.data

    def __repr__(self):
        return "msg_generic()"


class msg_getaddr:
    __slots__ = ()
    msgtype = b"getaddr"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_getaddr()"


class msg_ping:
    __slots__ = ("nonce",)
    msgtype = b"ping"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = struct.unpack("<Q", f.read(8))[0]

    def serialize(self):
        r = b""
        r += struct.pack("<Q", self.nonce)
        return r

    def __repr__(self):
        return "msg_ping(nonce={:08x})".format(self.nonce)


class msg_pong:
    __slots__ = ("nonce",)
    msgtype = b"pong"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = struct.unpack("<Q", f.read(8))[0]

    def serialize(self):
        r = b""
        r += struct.pack("<Q", self.nonce)
        return r

    def __repr__(self):
        return "msg_pong(nonce={:08x})".format(self.nonce)


class msg_mempool:
    __slots__ = ()
    msgtype = b"mempool"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_mempool()"


class msg_notfound:
    __slots__ = ("vec", )
    msgtype = b"notfound"

    def __init__(self, vec=None):
        self.vec = vec or []

    def deserialize(self, f):
        self.vec = deser_vector(f, CInv)

    def serialize(self):
        return ser_vector(self.vec)

    def __repr__(self):
        return "msg_notfound(vec={})".format(repr(self.vec))


class msg_sendheaders:
    __slots__ = ()
    msgtype = b"sendheaders"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_sendheaders()"


# getheaders message has
# number of entries
# vector of hashes
# hash_stop (hash of last desired block header, 0 to get as many as possible)
class msg_getheaders:
    __slots__ = ("hashstop", "locator",)
    msgtype = b"getheaders"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getheaders(locator={}, stop={:064x})".format(
            repr(self.locator), self.hashstop)


# headers message has
# <count> <vector of block headers>
class msg_headers:
    __slots__ = ("headers",)
    msgtype = b"headers"

    def __init__(self, headers=None):
        self.headers = headers if headers is not None else []

    def deserialize(self, f):
        # comment in bitcoind indicates these should be deserialized as blocks
        blocks = deser_vector(f, CBlock)
        for x in blocks:
            self.headers.append(CBlockHeader(x))

    def serialize(self):
        blocks = [CBlock(x) for x in self.headers]
        return ser_vector(blocks)

    def __repr__(self):
        return "msg_headers(headers={})".format(repr(self.headers))


class msg_reject:
    __slots__ = ("code", "data", "message", "reason")
    msgtype = b"reject"
    REJECT_MALFORMED = 1

    def __init__(self):
        self.message = b""
        self.code = 0
        self.reason = b""
        self.data = 0

    def deserialize(self, f):
        self.message = deser_string(f)
        self.code = struct.unpack("<B", f.read(1))[0]
        self.reason = deser_string(f)
        if (self.code != self.REJECT_MALFORMED
                and (self.message == b"block" or self.message == b"tx")):
            self.data = deser_uint256(f)

    def serialize(self):
        r = ser_string(self.message)
        r += struct.pack("<B", self.code)
        r += ser_string(self.reason)
        if (self.code != self.REJECT_MALFORMED
                and (self.message == b"block" or self.message == b"tx")):
            r += ser_uint256(self.data)
        return r

    def __repr__(self):
        return "msg_reject: {} {} {} [{:064x}]".format(
            self.message, self.code, self.reason, self.data)


class msg_merkleblock:
    __slots__ = ("merkleblock",)
    msgtype = b"merkleblock"

    def __init__(self, merkleblock=None):
        if merkleblock is None:
            self.merkleblock = CMerkleBlock()
        else:
            self.merkleblock = merkleblock

    def deserialize(self, f):
        self.merkleblock.deserialize(f)

    def serialize(self):
        return self.merkleblock.serialize()

    def __repr__(self):
        return "msg_merkleblock(merkleblock={})".format(repr(self.merkleblock))


class msg_filterload:
    __slots__ = ("data", "nHashFuncs", "nTweak", "nFlags")
    msgtype = b"filterload"

    def __init__(self, data=b'00', nHashFuncs=0, nTweak=0, nFlags=0):
        self.data = data
        self.nHashFuncs = nHashFuncs
        self.nTweak = nTweak
        self.nFlags = nFlags

    def deserialize(self, f):
        self.data = deser_string(f)
        self.nHashFuncs = struct.unpack("<I", f.read(4))[0]
        self.nTweak = struct.unpack("<I", f.read(4))[0]
        self.nFlags = struct.unpack("<B", f.read(1))[0]

    def serialize(self):
        r = b""
        r += ser_string(self.data)
        r += struct.pack("<I", self.nHashFuncs)
        r += struct.pack("<I", self.nTweak)
        r += struct.pack("<B", self.nFlags)
        return r

    def __repr__(self):
        return "msg_filterload(data={}, nHashFuncs={}, nTweak={}, nFlags={})".format(
            self.data, self.nHashFuncs, self.nTweak, self.nFlags)


class msg_filteradd:
    __slots__ = ("data")
    msgtype = b"filteradd"

    def __init__(self, data):
        self.data = data

    def deserialize(self, f):
        self.data = deser_string(f)

    def serialize(self):
        r = b""
        r += ser_string(self.data)
        return r

    def __repr__(self):
        return "msg_filteradd(data={})".format(self.data)


class msg_filterclear:
    __slots__ = ()
    msgtype = b"filterclear"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_filterclear()"


class msg_feefilter:
    __slots__ = ("feerate",)
    msgtype = b"feefilter"

    def __init__(self, feerate=0):
        self.feerate = feerate

    def deserialize(self, f):
        self.feerate = struct.unpack("<Q", f.read(8))[0]

    def serialize(self):
        r = b""
        r += struct.pack("<Q", self.feerate)
        return r

    def __repr__(self):
        return "msg_feefilter(feerate={:08x})".format(self.feerate)


class msg_sendcmpct:
    __slots__ = ("announce", "version")
    msgtype = b"sendcmpct"

    def __init__(self, announce=None, version=None):
        self.announce = False if announce is None else announce
        self.version = 1 if version is None else version

    def deserialize(self, f):
        self.announce = struct.unpack("<?", f.read(1))[0]
        self.version = struct.unpack("<Q", f.read(8))[0]

    def serialize(self):
        r = b""
        r += struct.pack("<?", self.announce)
        r += struct.pack("<Q", self.version)
        return r

    def __repr__(self):
        return "msg_sendcmpct(announce={}, version={})".format(
            self.announce, self.version)


class msg_cmpctblock:
    __slots__ = ("header_and_shortids",)
    msgtype = b"cmpctblock"

    def __init__(self, header_and_shortids=None):
        self.header_and_shortids = header_and_shortids

    def deserialize(self, f):
        self.header_and_shortids = P2PHeaderAndShortIDs()
        self.header_and_shortids.deserialize(f)

    def serialize(self):
        r = b""
        r += self.header_and_shortids.serialize()
        return r

    def __repr__(self):
        return "msg_cmpctblock(HeaderAndShortIDs={})".format(
            repr(self.header_and_shortids))


class msg_getblocktxn:
    __slots__ = ("block_txn_request",)
    msgtype = b"getblocktxn"

    def __init__(self):
        self.block_txn_request = None

    def deserialize(self, f):
        self.block_txn_request = BlockTransactionsRequest()
        self.block_txn_request.deserialize(f)

    def serialize(self):
        r = b""
        r += self.block_txn_request.serialize()
        return r

    def __repr__(self):
        return "msg_getblocktxn(block_txn_request={})".format(
            repr(self.block_txn_request))


class msg_blocktxn:
    __slots__ = ("block_transactions",)
    msgtype = b"blocktxn"

    def __init__(self):
        self.block_transactions = BlockTransactions()

    def deserialize(self, f):
        self.block_transactions.deserialize(f)

    def serialize(self):
        r = b""
        r += self.block_transactions.serialize()
        return r

    def __repr__(self):
        return "msg_blocktxn(block_transactions={})".format(
            repr(self.block_transactions))
