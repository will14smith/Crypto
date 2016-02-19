using System.Collections.Generic;
using Crypto.Encryption;
using Crypto.Encryption.Block;
using Crypto.Encryption.Modes;
using Crypto.Encryption.Parameters;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.Encryption.Modes
{
    [TestClass]
    public class CBCBlockModeTests
    {
        [TestMethod]
        public void AESCBC128Test()
        {
            var aes = new AESCipher(128);
            aes.Init(new KeyParameter(HexConverter.FromHex("2b7e151628aed2a6abf7158809cf4f3c")));

            var tests = new[]
            {
                new[] { "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d4cbbc858756b358125529e9698a38f44"},
            };

            RunTests(tests, aes);
        }

        private static void RunTests(IEnumerable<string[]> tests, AESCipher aes)
        {
            foreach (var test in tests)
            {
                var iv = test[0];
                var plaintext = test[1];
                var ciphertext = test[2];

                var cbc = new CBCBlockCipher(aes);
                var cipher = new BlockCipherAdapter(cbc);

                // encryption
                var plainInput = HexConverter.FromHex(plaintext);
                var actual = new byte[plainInput.Length];

                cipher.Init(new IVParameter(null, HexConverter.FromHex(iv)));
                cipher.Encrypt(plainInput, 0, actual, 0, plainInput.Length);

                Assert.AreEqual(ciphertext, HexConverter.ToHex(actual));



                // decryption
                var cipherInput = HexConverter.FromHex(ciphertext);
                actual = new byte[cipherInput.Length];

                cipher.Init(new IVParameter(null, HexConverter.FromHex(iv)));
                cipher.Decrypt(cipherInput, 0, actual, 0, cipherInput.Length);

                Assert.AreEqual(plaintext, HexConverter.ToHex(actual));
            }
        }

    }
}
