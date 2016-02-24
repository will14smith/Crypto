using Crypto.Encryption.Block;
using Crypto.Encryption.Parameters;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.GCM.Tests
{
    [TestClass]
    public class GCMCipherTests
    {
        [TestMethod]
        public void TestAES128()
        {
            var key = "ad7a2bd03eac835a6f620fdcb506b345";
            var iv = "12153524c0895e81b2c28465";
            var aad = "d609b1f056637a0d46df998d88e52e00b2c2846512153524c0895e81";

            var plaintext = "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002";
            var ciphertext = "701afa1cc039c0d765128a665dab69243899bf7318ccdc81c9931da17fbe8edd7d17cb8b4c26fc81e3284f2b7fba713d";
            var tag = "4f8d55e7d3f06fd5a13c0c29b9d5b880";

            var aes = new AESCipher(128);
            var gcm = new GCMCipher(aes);

            // encryption
            gcm.Init(new AADParameter(new IVParameter(new KeyParameter(HexConverter.FromHex(key)), HexConverter.FromHex(iv)), HexConverter.FromHex(aad)));

            var encryptInput = HexConverter.FromHex(plaintext);
            var encryptOutput = new byte[encryptInput.Length];
            var encryptTag = new byte[16];

            gcm.Encrypt(encryptInput, 0, encryptOutput, 0, encryptInput.Length);
            gcm.EncryptFinal(encryptTag, 0);

            Assert.AreEqual(ciphertext, HexConverter.ToHex(encryptOutput));
            Assert.AreEqual(tag, HexConverter.ToHex(encryptTag));

            // decryption
            gcm.Init(new AADParameter(new IVParameter(new KeyParameter(HexConverter.FromHex(key)), HexConverter.FromHex(iv)), HexConverter.FromHex(aad)));

            var decryptInput = HexConverter.FromHex(ciphertext + tag);
            var decryptOutput = new byte[decryptInput.Length - 16];

            var offset = gcm.Decrypt(decryptInput, 0, decryptOutput, 0, decryptInput.Length);
            gcm.DecryptFinal(decryptInput, offset, decryptOutput, decryptInput.Length);

            Assert.AreEqual(plaintext, HexConverter.ToHex(decryptOutput));
        }
    }
}
