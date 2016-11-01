using System.IO;
using Crypto.ASN1;

namespace Crypto.Certificates.Keys
{
    public class PrivateKeyReader
    {
        private readonly byte[] input;

        public PrivateKeyReader(byte[] input)
        {
            this.input = DERReadingHelper.TryConvertFromBase64(input).Item2;
        }

        public PrivateKey ReadKey()
        {
            ASN1Object asn1;
            using (var ms = new MemoryStream(input))
            {
                asn1 = new DERReader(ms).Read();
            }

            // NOTE: currently only supporting RSA private keys
            return new RSAPrivateKey(asn1);
        }
    }
}
