import copy
import unittest

from brisart_security_envelope import BrisartEnvelopeError, decrypt, encrypt
from brisart_security_drbg import BrisartDRBG, BrisartDRBGError
from brisart_security_primitives import (
    derive_password_key,
    hex_decode,
    hex_encode,
    sponge_hash,
)


class BrisartCipherResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kdf_salt = bytes(range(32))
        cls.master_key = derive_password_key(
            "research-only-password",
            cls.kdf_salt,
            iterations=10_000,
        )
        cls.context = "research-record:test"
        cls.seed = bytes(range(64))
        cls.plaintext = "Custom cipher research: café archive".encode("utf-8")

    def test_round_trip(self) -> None:
        envelope = encrypt(self.master_key, self.plaintext, self.context, BrisartDRBG(self.seed, b"BRC1 test instance"))
        self.assertEqual(decrypt(self.master_key, envelope, self.context), self.plaintext)

    def test_randomized_encryption(self) -> None:
        generator = BrisartDRBG(self.seed, b"BRC1 test instance")
        first = encrypt(self.master_key, self.plaintext, self.context, generator)
        second = encrypt(self.master_key, self.plaintext, self.context, generator)
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_each_binary_field_tamper_fails(self) -> None:
        for field in ("salt", "nonce", "ciphertext", "tag"):
            with self.subTest(field=field):
                envelope = encrypt(self.master_key, self.plaintext, self.context, BrisartDRBG(self.seed, b"BRC1 test instance"))
                raw = bytearray(hex_decode(envelope[field]))
                if raw:
                    raw[0] ^= 1
                else:
                    raw.append(1)
                envelope[field] = hex_encode(bytes(raw))
                with self.assertRaises(BrisartEnvelopeError):
                    decrypt(self.master_key, envelope, self.context)

    def test_wrong_context_fails(self) -> None:
        envelope = encrypt(self.master_key, self.plaintext, self.context, BrisartDRBG(self.seed, b"BRC1 test instance"))
        with self.assertRaises(BrisartEnvelopeError):
            decrypt(self.master_key, envelope, "other-context")

    def test_wrong_key_fails(self) -> None:
        envelope = encrypt(self.master_key, self.plaintext, self.context, BrisartDRBG(self.seed, b"BRC1 test instance"))
        wrong_key = BrisartDRBG(bytes(reversed(self.seed)), b"BRC1 wrong key test").generate(32, b"wrong key generation")
        with self.assertRaises(BrisartEnvelopeError):
            decrypt(wrong_key, envelope, self.context)

    def test_unknown_missing_and_format_fields_fail(self) -> None:
        envelope = encrypt(self.master_key, self.plaintext, self.context, BrisartDRBG(self.seed, b"BRC1 test instance"))
        for mutation in ("extra", "missing", "algorithm", "version"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(envelope)
                if mutation == "extra":
                    changed["extra"] = 1
                elif mutation == "missing":
                    del changed["tag"]
                elif mutation == "algorithm":
                    changed["algorithm"] = "other"
                else:
                    changed["version"] = 2
                with self.assertRaises(BrisartEnvelopeError):
                    decrypt(self.master_key, changed, self.context)

    def test_empty_plaintext(self) -> None:
        envelope = encrypt(
            self.master_key, b"", self.context, BrisartDRBG(self.seed, b"BRC1 test instance")
        )
        self.assertEqual(decrypt(self.master_key, envelope, self.context), b"")

    def test_custom_hex_codec(self) -> None:
        value = bytes(range(256))
        self.assertEqual(hex_decode(hex_encode(value)), value)

    def test_hash_is_deterministic(self) -> None:
        self.assertEqual(sponge_hash(b"message"), sponge_hash(b"message"))
        self.assertNotEqual(sponge_hash(b"message"), sponge_hash(b"messagf"))

    def test_avalanche_observation(self) -> None:
        first = sponge_hash(b"A" * 64)
        changed = bytearray(b"A" * 64)
        changed[0] ^= 1
        second = sponge_hash(bytes(changed))
        differing_bits = sum((a ^ b).bit_count() for a, b in zip(first, second))
        self.assertGreater(differing_bits, 80)
        self.assertLess(differing_bits, 176)

    def test_drbg_is_deterministic_for_same_seed(self) -> None:
        first = BrisartDRBG(self.seed, b"BRC1 test instance").generate(96, b"deterministic test")
        second = BrisartDRBG(self.seed, b"BRC1 test instance").generate(96, b"deterministic test")
        self.assertEqual(first, second)

    def test_drbg_changes_with_seed(self) -> None:
        first = BrisartDRBG(self.seed, b"BRC1 test instance").generate(96, b"deterministic test")
        second_seed = bytearray(self.seed)
        second_seed[0] ^= 1
        second = BrisartDRBG(bytes(second_seed), b"BRC1 test instance").generate(96, b"deterministic test")
        self.assertNotEqual(first, second)

    def test_drbg_rejects_short_seed(self) -> None:
        with self.assertRaises(BrisartDRBGError):
            BrisartDRBG(b"short", b"BRC1 short seed test")

    def test_encryption_requires_explicit_generator(self) -> None:
        with self.assertRaises(BrisartEnvelopeError):
            encrypt(self.master_key, self.plaintext, self.context, None)


    def test_drbg_requires_personalization(self) -> None:
        with self.assertRaises(BrisartDRBGError):
            BrisartDRBG(self.seed, b"short")

    def test_drbg_requires_additional_input(self) -> None:
        generator = BrisartDRBG(self.seed, b"BRC1 additional input")
        with self.assertRaises(BrisartDRBGError):
            generator.generate(32, b"")

    def test_destroyed_drbg_fails_closed(self) -> None:
        generator = BrisartDRBG(self.seed, b"BRC1 destroy test")
        generator.destroy()
        with self.assertRaises(BrisartDRBGError):
            generator.generate(32, b"after destroy")

    def test_reseed_changes_output(self) -> None:
        generator = BrisartDRBG(self.seed, b"BRC1 reseed test")
        before = generator.generate(64, b"before reseed")
        generator.reseed(bytes(reversed(self.seed)), b"reseed event")
        after = generator.generate(64, b"after reseed")
        self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
