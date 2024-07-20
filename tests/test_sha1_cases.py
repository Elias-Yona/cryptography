import unittest
from crypto.sha1.context import SHA1Context
from crypto.sha1.sha1 import SHA1Reset, SHA1Input, SHA1Result, SHA_STATE_ERROR, SHA_NULL, SHA_SUCCESS

class TestSHA1Cases(unittest.TestCase):

    def setUp(self):
        self.testarray = [
            "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "a",
            "0123456701234567012345670123456701234567012345670123456701234567"
        ]
        self.repeatcount = [
            1,
            1,
            1000000,
            10
        ]
        self.resultarray = [
            "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
            "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
            "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
            "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
        ]

    def test_sha1_cases(self):
        for j in range(4):
            sha = SHA1Context()
            message_digest = [0] * 20

            print(f"\nTest {j + 1}: {self.repeatcount[j]}, '{self.testarray[j]}'")

            err = SHA1Reset(sha)
            self.assertEqual(err, 0, f"SHA1Reset Error {err}.")

            for i in range(self.repeatcount[j]):
                err = SHA1Input(sha, [ord(c) for c in self.testarray[j]], len(self.testarray[j]))
                self.assertEqual(err, 0, f"SHA1Input Error {err}.")

            err = SHA1Result(sha, message_digest)
            self.assertEqual(err, 0, f"SHA1Result Error {err}, could not compute message digest.")

            result_str = " ".join([f"{byte:02X}" for byte in message_digest])
            print("\t" + result_str)
            print("Should match:")
            print("\t" + self.resultarray[j])
            self.assertEqual(result_str, self.resultarray[j], f"Test {j + 1} failed.")

    def test_sha1_errors(self):
        sha = SHA1Context()
        # Set `computed` to true to test SHA_STATE_ERROR
        err = SHA1Input(sha, [ord(c) for c in self.testarray[1]], 1)
        self.assertEqual(err, SHA_SUCCESS, f"Initial SHA1Input Error {err}.")

        # Compute the result to set `computed` to True
        err = SHA1Result(sha, [0] * 20)
        self.assertEqual(err, 0, f"SHA1Result Error {err}.")

        err = SHA1Input(sha, [ord(c) for c in self.testarray[1]], 1)
        self.assertEqual(err, SHA_STATE_ERROR, f"Expected SHA_STATE_ERROR, got {err}.")

        # Test invalid context
        err = SHA1Reset(None)
        self.assertEqual(err, SHA_NULL, f"Expected SHA_NULL, got {err}.")

if __name__ == '__main__':
    unittest.main()
