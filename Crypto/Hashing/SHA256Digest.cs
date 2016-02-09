using System;
using Crypto.ASN1;

namespace Crypto.Hashing
{
    class SHA256Digest : IDigest
    {
        public ASN1ObjectIdentifier Id => new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

        public void Update(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }

        public byte[] Digest()
        {
            throw new NotImplementedException();
        }
    }
}
