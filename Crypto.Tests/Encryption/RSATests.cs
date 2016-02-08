using System;
using System.Text;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.Encryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.Encryption
{
    [TestClass]
    public class RSATests
    {
        internal static PrivateKey Key = new PrivateKeyReader(Convert.FromBase64String("MIIBOwIBAAJBAMrK7ObRkpDkRgfjPRN2fFhVvfHByK4VCo+X7qOmcaYdP1ekHXfOQYcwwPLUwM6iZoYM0QGpGoJLJiJeWM8rkpECAwEAAQJAewlXZktsk0AMRSjXm4Fdu/J5hb4+1W+qsqhJfzyy40byZW1RVZ6nf9VQwg21sB0PCPZpPqwDR8582BAd4VQcqQIhAPLoGNX9CRxBfNzuHiP3k+vMOCC3lVpPp7CGVm629+azAiEA1blKT9FNEF7R2cxmn/HImn4MWlgG/YfBIsVLVjXOI6sCIQCzXiQI0CLMFKepVMQ49vbp5hGER0woNi2zsl9cvgts9QIhAMqyrTP+QaShCU4TedGAMs2zdmvIyPhzZE1h6Q2egh95AiA+MprDyZjZ+zjqgSD/Kkp82vSy04iF5ZBvrBhtS0vK0Q==")).ReadKey();

        [TestMethod]
        public void TestEncryptionDecryption()
        {
            var input = new byte[] { 0, 1, 5, 30, 244, 255, 193 };

            var rsa = new RSA(Key);

            var encrypted = rsa.Encrypt(input);
            var decrypted = rsa.Decrypt(encrypted);

            CollectionAssert.AreEqual(input, decrypted);
        }
    }
}
