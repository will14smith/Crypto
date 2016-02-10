using System;
using System.IO;
using System.Text;
using Crypto.Hashing;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.Hashing
{
    [TestClass]
    public class SHA256DigestTests
    {
        [TestMethod]
        public void GivesCorrectOutputWithNoInput()
        {
            var digest = new SHA256Digest();

            var result = digest.Digest();

            AssertSHA256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result);
        }

        [TestMethod]
        public void GivesCorrectOutputWithSimpleStringInput()
        {
            var digest = new SHA256Digest();

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.Digest();

            AssertSHA256("09fc96082d34c2dfc1295d92073b5ea1dc8ef8da95f14dfded011ffb96d3e54b", result);
        }

        [TestMethod]
        public void GivesCorrectOutputWithStringInput()
        {
            var digest = new SHA256Digest();

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.Digest();

            AssertSHA256("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", result);
        }

        [TestMethod]
        public void NISTShortVectors()
        {
            RunNIST("SHA256ShortMsg.dat");
        }

        [TestMethod]
        public void NISTLongVectors()
        {
            RunNIST("SHA256LongMsg.dat");
        }

        private void RunNIST(string file)
        {
            var lines = File.ReadAllLines("Hashing/TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA256Digest();

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg, 0, len);
                var hash = digest.Digest();

                AssertSHA256(expectedHash, hash);
            }
        }

        private void AssertSHA256(string expected, byte[] actual)
        {
            Assert.IsNotNull(actual);
            Assert.AreEqual(32, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            CollectionAssert.AreEqual(expectedBuffer, actual);
        }
    }
}
