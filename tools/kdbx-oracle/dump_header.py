"""Разбор outer header файла .kdbx: версия формата, шифр, KDF и его параметры.

Чистый stdlib — работает без venv и без pykeepass. Нужен, чтобы быстро понять,
что за файл перед нами (например, почему core его не читает).

Использование:
    python tools/kdbx-oracle/dump_header.py path/to/db.kdbx [...]
"""

import struct
import sys

if hasattr(sys.stdout, "reconfigure"):
    # Windows-консоль не utf-8 по умолчанию
    sys.stdout.reconfigure(encoding="utf-8")
import uuid

SIG1 = 0x9AA2D903
SIG2 = 0xB54BFB67

CIPHERS = {
    "31c1f2e6-bf71-4350-be58-05216afc5aff": "AES-256/CBC",
    "d6038a2b-8b6f-4cb5-a524-339a31dbb59a": "ChaCha20",
    "ad68f29f-576f-4bb9-a36a-d47af965346c": "Twofish (наш core НЕ поддерживает)",
}

KDFS = {
    "ef636ddf-8c29-444b-91f7-a9a403e30a0c": "Argon2d",
    "9e298b19-56db-4773-b23d-fc3ec6f0a1e6": "Argon2id",
    "c9d9f39a-628a-4460-bf74-0d08c18a4fea": "AES-KDF (наш core НЕ поддерживает)",
}

FIELD_NAMES = {
    0: "EndOfHeader",
    1: "Comment",
    2: "CipherID",
    3: "CompressionFlags",
    4: "MasterSeed",
    5: "TransformSeed (KDBX3)",
    6: "TransformRounds (KDBX3)",
    7: "EncryptionIV",
    8: "InnerRandomStreamKey (KDBX3)",
    9: "StreamStartBytes (KDBX3)",
    10: "InnerRandomStreamID (KDBX3)",
    11: "KdfParameters (KDBX4)",
    12: "PublicCustomData (KDBX4)",
}

STREAM_IDS = {0: "none", 1: "ArcFourVariant", 2: "Salsa20 (наш core НЕ поддерживает)", 3: "ChaCha20"}


def parse_variant_dict(data):
    """VariantDictionary из KdfParameters (KDBX4)."""
    out = {}
    pos = 2  # первые 2 байта — версия словаря
    while pos < len(data):
        value_type = data[pos]
        pos += 1
        if value_type == 0:
            break
        key_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        key = data[pos:pos + key_len].decode()
        pos += key_len
        val_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        raw = data[pos:pos + val_len]
        pos += val_len

        if value_type == 0x04:
            value = struct.unpack("<I", raw)[0]
        elif value_type == 0x05:
            value = struct.unpack("<Q", raw)[0]
        elif value_type == 0x08:
            value = bool(raw[0])
        elif value_type == 0x0C:
            value = struct.unpack("<i", raw)[0]
        elif value_type == 0x0D:
            value = struct.unpack("<q", raw)[0]
        elif value_type == 0x18:
            value = raw.decode()
        else:
            value = raw
        out[key] = value
    return out


def dump(path):
    with open(path, "rb") as handle:
        data = handle.read()

    sig1, sig2, version = struct.unpack_from("<III", data, 0)
    major, minor = version >> 16, version & 0xFFFF
    print("== %s  (%d bytes)" % (path, len(data)))
    if (sig1, sig2) != (SIG1, SIG2):
        print("   НЕ файл KeePass: sig1=%08x sig2=%08x" % (sig1, sig2))
        return
    note = "" if major == 4 else "  <-- наш core читает только KDBX 4.x"
    print("   формат      : KDBX %d.%d%s" % (major, minor, note))

    pos = 12
    while True:
        field_id = data[pos]
        if major >= 4:
            length = struct.unpack_from("<I", data, pos + 1)[0]
            head = 5
        else:
            length = struct.unpack_from("<H", data, pos + 1)[0]
            head = 3
        payload = data[pos + head:pos + head + length]
        pos += head + length
        if field_id == 0:
            break

        name = FIELD_NAMES.get(field_id, "unknown(%d)" % field_id)
        if field_id == 2:
            key = str(uuid.UUID(bytes=payload))
            print("   шифр        : %s" % CIPHERS.get(key, key))
        elif field_id == 3:
            flag = struct.unpack("<I", payload)[0]
            print("   сжатие      : %s" % ("gzip" if flag == 1 else "нет"))
        elif field_id == 7:
            print("   IV          : %d байт" % length)
        elif field_id == 6 and length == 8:
            print("   KDF         : AES-KDF, %d раундов" % struct.unpack("<Q", payload)[0])
        elif field_id == 10 and length == 4:
            sid = struct.unpack("<I", payload)[0]
            print("   inner stream: %s" % STREAM_IDS.get(sid, sid))
        elif field_id == 11:
            params = parse_variant_dict(payload)
            key = str(uuid.UUID(bytes=params.pop("$UUID")))
            print("   KDF         : %s" % KDFS.get(key, key))
            memory = params.get("M")
            if memory:
                print("      память   : %d байт (%.0f MB)" % (memory, memory / 1024 / 1024))
            for label, field in (("итерации ", "I"), ("parallel ", "P"), ("версия   ", "V")):
                if field in params:
                    print("      %s: %s" % (label, params[field]))
            if "S" in params:
                print("      соль     : %d байт" % len(params["S"]))
        else:
            print("   %-12s: %d байт" % (name, length))

    print("   header      : %d байт" % pos)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    for path in sys.argv[1:]:
        dump(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
