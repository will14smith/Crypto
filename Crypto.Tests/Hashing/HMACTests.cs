using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.Hashing;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.Hashing
{
    [TestClass]
    public class HMACTests
    {
        [TestMethod]
        public void GivesCorrectOutputWithBlankKeyAndInputSHA1()
        {
            var hmac = new HMAC(new SHA1Digest(), new byte[0]);

            var output = hmac.Digest();

            AssertOutput(20, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d", output);
        }
        [TestMethod]
        public void GivesCorrectOutputWithBlankKeyAndInputSHA256()
        {
            var hmac = new HMAC(new SHA256Digest(), new byte[0]);

            var output = hmac.Digest();

            AssertOutput(32, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", output);
        }
        [TestMethod]
        public void GivesCorrectOutputSHA1()
        {
            var key = Encoding.UTF8.GetBytes("key");
            var hmac = new HMAC(new SHA1Digest(), key);

            var message = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

            hmac.Update(message, 0, message.Length);
            var output = hmac.Digest();

            AssertOutput(20, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", output);
        }
        [TestMethod]
        public void GivesCorrectOutputSHA256()
        {
            var key = Encoding.UTF8.GetBytes("key");
            var hmac = new HMAC(new SHA256Digest(), key);

            var message = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

            hmac.Update(message, 0, message.Length);
            var output = hmac.Digest();

            AssertOutput(32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", output);
        }
        [TestMethod]
        public void GivesCorrectOutputSHA256LongKey()
        {
            var key = Encoding.UTF8.GetBytes("Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World");
            var hmac = new HMAC(new SHA256Digest(), key);

            var message = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

            hmac.Update(message, 0, message.Length);
            var output = hmac.Digest();

            AssertOutput(32, "bcac0ae627a2be9e3ae2eb2ff367a54b15706af61f33aea3d6a0faa2ba68feef", output);
        }

        private void AssertOutput(int length, string expected, byte[] actual)
        {
            Assert.IsNotNull(actual);
            Assert.AreEqual(length, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            CollectionAssert.AreEqual(expectedBuffer, actual);
        }
    }
}
