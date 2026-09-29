import random
import struct

# =====================================================================
# AES S-Box & Rcon Constants
# =====================================================================

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [0] * 256
for idx, val in enumerate(SBOX):
    INV_SBOX[val] = idx

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


# =====================================================================
# AES Primitive
# =====================================================================

class AES:
    def __init__(self, key: bytes):
        key_len = len(key)
        if key_len not in (16, 24, 32):
            raise ValueError("Key length must be 16, 24, or 32 bytes.")

        self.Nk = key_len // 4
        self.Nr = self.Nk + 6
        self.round_keys = self._key_expansion(key)

    def _sub_word(self, word: list[int]) -> list[int]:
        return [SBOX[b] for b in word]

    def _rot_word(self, word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    def _key_expansion(self, key: bytes) -> list[list[int]]:
        w = []
        for i in range(self.Nk):
            w.append(list(key[4 * i : 4 * i + 4]))

        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = list(w[i - 1])
            if i % self.Nk == 0:
                temp = self._sub_word(self._rot_word(temp))
                temp[0] ^= RCON[i // self.Nk]
            elif self.Nk > 6 and (i % self.Nk == 4):
                temp = self._sub_word(temp)
            w.append([b1 ^ b2 for b1, b2 in zip(w[i - self.Nk], temp)])

        round_keys = []
        for r in range(self.Nr + 1):
            rk = [[0] * 4 for _ in range(4)]
            for col in range(4):
                for row in range(4):
                    rk[row][col] = w[r * 4 + col][row]
            round_keys.append(rk)
        return round_keys

    @staticmethod
    def _xtime(a: int) -> int:
        return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1)

    @staticmethod
    def _gmul(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xff
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    def _add_round_key(self, state: list[list[int]], rk: list[list[int]]) -> None:
        for r in range(4):
            for c in range(4):
                state[r][c] ^= rk[r][c]

    def _sub_bytes(self, state: list[list[int]]) -> None:
        for r in range(4):
            for c in range(4):
                state[r][c] = SBOX[state[r][c]]

    def _inv_sub_bytes(self, state: list[list[int]]) -> None:
        for r in range(4):
            for c in range(4):
                state[r][c] = INV_SBOX[state[r][c]]

    def _shift_rows(self, state: list[list[int]]) -> None:
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    def _inv_shift_rows(self, state: list[list[int]]) -> None:
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

    def _mix_columns(self, s: list[list[int]]) -> None:
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            t = a0 ^ a1 ^ a2 ^ a3
            s[0][c] ^= t ^ self._xtime(a0 ^ a1)
            s[1][c] ^= t ^ self._xtime(a1 ^ a2)
            s[2][c] ^= t ^ self._xtime(a2 ^ a3)
            s[3][c] ^= t ^ self._xtime(a3 ^ a0)

    def _inv_mix_columns(self, s: list[list[int]]) -> None:
        for c in range(4):
            u0, u1, u2, u3 = s[0][c], s[1][c], s[2][c], s[3][c]
            s[0][c] = self._gmul(u0, 0x0e) ^ self._gmul(u1, 0x0b) ^ self._gmul(u2, 0x0d) ^ self._gmul(u3, 0x09)
            s[1][c] = self._gmul(u0, 0x09) ^ self._gmul(u1, 0x0e) ^ self._gmul(u2, 0x0b) ^ self._gmul(u3, 0x0d)
            s[2][c] = self._gmul(u0, 0x0d) ^ self._gmul(u1, 0x09) ^ self._gmul(u2, 0x0e) ^ self._gmul(u3, 0x0b)
            s[3][c] = self._gmul(u0, 0x0b) ^ self._gmul(u1, 0x0d) ^ self._gmul(u2, 0x09) ^ self._gmul(u3, 0x0e)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block must be exactly 16 bytes.")
        state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

        self._add_round_key(state, self.round_keys[0])
        for r in range(1, self.Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[r])

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.Nr])

        return bytes(state[r][c] for c in range(4) for r in range(4))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block must be exactly 16 bytes.")
        state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

        self._add_round_key(state, self.round_keys[self.Nr])
        for r in range(self.Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self.round_keys[r])
            self._inv_mix_columns(state)

        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self.round_keys[0])

        return bytes(state[r][c] for c in range(4) for r in range(4))


# =====================================================================
# Utilities: Padding & Bitwise Helpers
# =====================================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def vulnerable_pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("DecryptionError: Invalid block length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("PaddingError: Byte value out of bounds")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PaddingError: Inconsistent padding sequence")
    return data[:-pad_len]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def insecure_random_bytes(n: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(n)])


# =====================================================================
# GHASH over GF(2^128)
# =====================================================================

def _gf_mult_128(x: int, y: int) -> int:
    R = 0xE1000000000000000000000000000000
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z

def ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h_int = int.from_bytes(h, "big")
    y = 0

    def process_data(data: bytes):
        nonlocal y
        for i in range(0, len(data), 16):
            block = data[i:i + 16].ljust(16, b"\x00")
            y ^= int.from_bytes(block, "big")
            y = _gf_mult_128(y, h_int)

    process_data(aad)
    process_data(ciphertext)

    len_block = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    y ^= int.from_bytes(len_block, "big")
    y = _gf_mult_128(y, h_int)

    return y.to_bytes(16, "big")


# =====================================================================
# AES Block Modes (med innebygde sårbarheter)
# =====================================================================

class VulnerableAESCipher:
    @staticmethod
    def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
        iv = iv or insecure_random_bytes(16)
        cipher = AES(key)
        padded = pkcs7_pad(plaintext)
        out = bytearray()
        prev = iv
        for i in range(0, len(padded), 16):
            block = padded[i:i + 16]
            encrypted = cipher.encrypt_block(xor_bytes(block, prev))
            out.extend(encrypted)
            prev = encrypted
        return iv, bytes(out)

    @staticmethod
    def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext must be a multiple of 16 bytes.")
        cipher = AES(key)
        out = bytearray()
        prev = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted = cipher.decrypt_block(block)
            out.extend(xor_bytes(decrypted, prev))
            prev = block
        return vulnerable_pkcs7_unpad(bytes(out))

    @staticmethod
    def encrypt_ctr(key: bytes, plaintext: bytes, nonce: bytes = None) -> tuple[bytes, bytes]:
        nonce = nonce or insecure_random_bytes(8)
        cipher = AES(key)
        out = bytearray()
        counter = 0

        for i in range(0, len(plaintext), 16):
            counter_block = nonce + struct.pack(">Q", counter)
            keystream = cipher.encrypt_block(counter_block)
            chunk = plaintext[i:i + 16]
            out.extend(xor_bytes(chunk, keystream[:len(chunk)]))
            counter += 1

        return nonce, bytes(out)

    @staticmethod
    def decrypt_ctr(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        _, pt = VulnerableAESCipher.encrypt_ctr(key, ciphertext, nonce)
        return pt

    @staticmethod
    def encrypt_gcm(key: bytes, plaintext: bytes, aad: bytes = b"", iv: bytes = None) -> tuple[bytes, bytes, bytes]:
        iv = iv or insecure_random_bytes(12)
        cipher = AES(key)
        h = cipher.encrypt_block(b"\x00" * 16)

        j0 = iv + b"\x00\x00\x00\x01" if len(iv) == 12 else ghash(h, b"", iv)

        j0_int = int.from_bytes(j0, "big")
        counter = (j0_int + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        ciphertext = bytearray()

        for i in range(0, len(plaintext), 16):
            counter_block = counter.to_bytes(16, "big")
            keystream = cipher.encrypt_block(counter_block)
            chunk = plaintext[i:i + 16]
            ciphertext.extend(xor_bytes(chunk, keystream[:len(chunk)]))
            counter = (counter + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        ciphertext = bytes(ciphertext)
        s = ghash(h, aad, ciphertext)
        tag = xor_bytes(s, cipher.encrypt_block(j0))
        return iv, ciphertext, tag

    @staticmethod
    def decrypt_gcm(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        cipher = AES(key)
        h = cipher.encrypt_block(b"\x00" * 16)

        j0 = iv + b"\x00\x00\x00\x01" if len(iv) == 12 else ghash(h, b"", iv)

        s = ghash(h, aad, ciphertext)
        expected_tag = xor_bytes(s, cipher.encrypt_block(j0))

        if expected_tag != tag:
            raise ValueError("Authentication failed: invalid tag.")

        j0_int = int.from_bytes(j0, "big")
        counter = (j0_int + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        plaintext = bytearray()

        for i in range(0, len(ciphertext), 16):
            counter_block = counter.to_bytes(16, "big")
            keystream = cipher.encrypt_block(counter_block)
            chunk = ciphertext[i:i + 16]
            plaintext.extend(xor_bytes(chunk, keystream[:len(chunk)]))
            counter = (counter + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        return bytes(plaintext)


# =====================================================================
# Padding Oracle Simulasjon og Angrep
# =====================================================================

GLOBAL_KEY = b"A" * 16  # Testnøkkel brukt internt av simulatoren

def padding_oracle(iv: bytes, ct: bytes) -> bool:
    """
    Orakelet simulerer en server-respons.
    Returnerer True hvis paddingen er gyldig, False hvis PaddingError oppstår.
    """
    try:
        VulnerableAESCipher.decrypt_cbc(GLOBAL_KEY, iv, ct)
        return True
    except ValueError as e:
        if "PaddingError" in str(e):
            return False
        return True


def attack_block(oracle, prev_block: bytes, target_block: bytes) -> bytes:
    """
    Gjenoppretter klarteksten for én 16-byte blokk (target_block) 
    ved å manipulere prev_block (enten forrige chiffertekstblokk eller IV).
    """
    block_size = 16
    intermediate = [0] * block_size
    recovered_pt = [0] * block_size

    # Arbeid bakfra: fra byte 15 ned til 0
    for byte_pos in range(block_size - 1, -1, -1):
        target_pad = block_size - byte_pos
        c_prime = bytearray(prev_block)

        # Forbered de bytene vi allerede har funnet (til høyre for byte_pos)
        for k in range(byte_pos + 1, block_size):
            c_prime[k] = intermediate[k] ^ target_pad

        found = False
        for guess in range(256):
            c_prime[byte_pos] = guess

            # Send modifisert 2-blokks sekvens [c_prime || target_block] til orakelet
            if oracle(bytes(c_prime), target_block):
                # Unngå falsk positiv ved padding 0x01 hvis opprinnelig data endte på f.eks. 0x02 0x02
                if target_pad == 1 and byte_pos > 0:
                    c_prime_check = bytearray(c_prime)
                    c_prime_check[byte_pos - 1] ^= 0x01
                    if not oracle(bytes(c_prime_check), target_block):
                        continue

                intermediate[byte_pos] = guess ^ target_pad
                recovered_pt[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                found = True
                break

        if not found:
            raise RuntimeError(f"Klarte ikke finne gyldig byte på posisjon {byte_pos}")

    return bytes(recovered_pt)


def padding_oracle_attack(iv: bytes, ciphertext: bytes) -> bytes:
    """
    Deler chifferteksten inn i blokker og kjører angrepet over alle blokker.
    """
    block_size = 16
    blocks = [iv] + [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    recovered_full = bytearray()

    for i in range(1, len(blocks)):
        prev_b = blocks[i - 1]
        curr_b = blocks[i]
        pt_block = attack_block(padding_oracle, prev_b, curr_b)
        recovered_full.extend(pt_block)

    pad_len = recovered_full[-1]
    return bytes(recovered_full[:-pad_len])


# =====================================================================
# Hovedkjøring
# =====================================================================

if __name__ == "__main__":
    hemmelig_melding = b"Hemmelig melding som skal krypteres og lekkes via CBC oracle!"

    print("[*] Krypterer melding med sårbar CBC-implementasjon...")
    iv, ct = VulnerableAESCipher.encrypt_cbc(GLOBAL_KEY, hemmelig_melding)

    print(f"[*] Chiffertekst lengde: {len(ct)} bytes ({len(ct) // 16} blokker)")
    print("[*] Starter Padding Oracle-angrep (kun ved kall mot padding_oracle)...\n")

    gjenopprettet = padding_oracle_attack(iv, ct)

    print("-" * 50)
    print(f"[+] Angrep fullført!")
    print(f"[+] Rekonstruert klartekst: {gjenopprettet.decode('utf-8', errors='replace')}")
    assert gjenopprettet == hemmelig_melding
    print("[+] Integritet bekreftet: 100% match med originalen.")
