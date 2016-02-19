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
    public class PRFTests
    {
        [TestMethod]
        public void SHA256Test()
        {
            var secret = "9bbe436ba940f017b17652849a71db35";
            var label = "test label";
            var seed = "a0ba9f936cda311827a6f796ffd5198c";

            var expected = "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66";

            var prf = new PRF(new SHA256Digest());

            var generator = prf.Digest(HexConverter.FromHex(secret), label, HexConverter.FromHex(seed));
            var output = generator.Take(100).ToArray();

            Assert.AreEqual(expected, HexConverter.ToHex(output));
        }
    }
}
