"""Authenticated encryption for state and history at rest.

AES-256-CBC (macOS CommonCrypto via ctypes, no third-party packages) with encrypt-then-MAC
HMAC-SHA256. Keys are derived from the 32-byte master key with HKDF-SHA256.
"""
import ctypes
import ctypes.util
import hashlib
import hmac
import os

MAGIC = b'PRE1'
_lib = None


def _commoncrypto():
    global _lib
    if _lib is None:
        path = ctypes.util.find_library('System') or '/usr/lib/libSystem.B.dylib'
        lib = ctypes.CDLL(path)
        lib.CCCrypt.restype = ctypes.c_int32
        lib.CCCrypt.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                ctypes.c_char_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        _lib = lib
    return _lib


def _cbc(op, key, iv, data):
    lib = _commoncrypto()
    out = ctypes.create_string_buffer(len(data) + 16)
    moved = ctypes.c_size_t(0)
    # kCCAlgorithmAES = 0, kCCOptionPKCS7Padding = 1
    status = lib.CCCrypt(op, 0, 1, key, len(key), iv, data, len(data), out, len(out),
                         ctypes.byref(moved))
    if status != 0:
        raise ValueError('CommonCrypto failure')
    return out.raw[:moved.value]


def hkdf(key, info, length=32):
    prk = hmac.new(b'passrelay-hkdf-salt', key, hashlib.sha256).digest()
    out, block, i = b'', b'', 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def seal(key, plaintext, aad=b''):
    enc, mac = hkdf(key, b'enc'), hkdf(key, b'mac')
    iv = os.urandom(16)
    body = MAGIC + iv + _cbc(0, enc, iv, plaintext)
    return body + hmac.new(mac, aad + body, hashlib.sha256).digest()


def open_(key, blob, aad=b''):
    if len(blob) < 4 + 16 + 16 + 32 or not blob.startswith(MAGIC):
        raise ValueError('not a PassRelay encrypted blob')
    enc, mac = hkdf(key, b'enc'), hkdf(key, b'mac')
    body, tag = blob[:-32], blob[-32:]
    if not hmac.compare_digest(tag, hmac.new(mac, aad + body, hashlib.sha256).digest()):
        raise ValueError('authentication failed')
    return _cbc(1, enc, body[4:20], body[20:])
