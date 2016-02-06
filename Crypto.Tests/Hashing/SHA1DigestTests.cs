using System;
using System.IO;
using System.Text;
using Crypto.Hashing;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.Hashing
{
    [TestClass]
    public class SHA1DigestTests
    {
        [TestMethod]
        public void GivesCorrectOutputWithNoInput()
        {
            var digest = new SHA1Digest();

            var result = digest.Digest();

            AssertSHA1("da39a3ee5e6b4b0d3255bfef95601890afd80709", result);
        }

        [TestMethod]
        public void GivesCorrectOutputWithSimpleStringInput()
        {
            var digest = new SHA1Digest();

            var buffer = new byte[] { 0x24 };
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.Digest();

            AssertSHA1("3cdf2936da2fc556bfa533ab1eb59ce710ac80e5", result);
        }

        [TestMethod]
        public void GivesCorrectOutputWithStringInput()
        {
            var digest = new SHA1Digest();

            var buffer = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            digest.Update(buffer, 0, buffer.Length);

            var result = digest.Digest();

            AssertSHA1("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", result);
        }

        [TestMethod]
        public void NISTShortVectors()
        {
            RunNIST("SHA1ShortMsg.dat");
        }

        [TestMethod]
        public void NISTLongVectors()
        {
            RunNIST("SHA1LongMsg.dat");
        }

        private void RunNIST(string file)
        {
            var lines = File.ReadAllLines("Hashing/TestVectors/" + file);

            for (var i = 0; i < lines.Length; i += 4)
            {
                var digest = new SHA1Digest();

                var len = int.Parse(lines[i].Substring(6)) / 8;
                var msg = HexConverter.FromHex(lines[i + 1].Substring(6));
                var expectedHash = lines[i + 2].Substring(5);

                digest.Update(msg, 0, len);
                var hash = digest.Digest();

                AssertSHA1(expectedHash, hash);
            }
        }

        private void AssertSHA1(string expected, byte[] actual)
        {
            Assert.IsNotNull(actual);
            Assert.AreEqual(20, actual.Length);

            var expectedBuffer = HexConverter.FromHex(expected);

            Console.WriteLine("Expecting : {0}", expected);
            Console.WriteLine("Actual    : {0}", HexConverter.ToHex(actual));

            CollectionAssert.AreEqual(expectedBuffer, actual);
        }
    }
}
