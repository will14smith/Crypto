using System.Text;
using Crypto.EllipticCurve.Algorithms;
using Crypto.EllipticCurve.Maths;
using Crypto.EllipticCurve.Maths.Curves;
using Crypto.Hashing;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.EllipticCurve.Tests.Math.Curves
{
    [TestClass]
    public class Secp256K1Tests
    {
        private static readonly ECPublicKey PublicKey = new ECPublicKey(PointUtils.FromBinary(Secp256K1.Parameters.Curve, HexConverter.FromHex("0487055e38dd31ef223763531f03fc0e82ab4643d845d8aade83f5ffbff71f7046d4735e68926df377f5f0e6ab68ced4a82f1884cd82ac91596eccc29d20561a8f")));
        private static readonly ECPrivateKey PrivateKey = new ECPrivateKey(
            BigIntegerExtensions.FromTlsHex("1dcc2c87bbd1b13f680022420b8f1b9d79ba18f6d46e1c7f53260c222f708848"),
            PublicKey);

        [TestMethod]
        public void TestSignature()
        {
            var input = Encoding.UTF8.GetBytes("Hello!");

            var ecdsa = new ECDSA();
            ecdsa.Init(new ECCipherParameters(Secp256K1.Parameters, PrivateKey));

            var signature = ecdsa.Sign(input, new SHA256Digest());
            var result = ecdsa.Verify(input, signature, new SHA256Digest());

            Assert.IsTrue(result);
        }

        // 

        [TestMethod]
        public void TestVerify()
        {
            var input = Encoding.UTF8.GetBytes("Hello!");
            var signature = HexConverter.FromHex("304602210098a1615b14266bb514f3829f2775e1a46eec972c1021d67dd1c35b88add5e3f6022100eb91ddd49f9ab3560d69d65b47961fb051ef72c18c3c9acd7f2fb4d1c37ce351");

            var ecdsa = new ECDSA();
            ecdsa.Init(new ECCipherParameters(Secp256K1.Parameters, PublicKey));

            var result = ecdsa.Verify(input, signature, new SHA256Digest());

            Assert.IsTrue(result);
        }

    }
}
