using System;
using Crypto.ASN1;

namespace Crypto.Hashing
{
    class MD5Digest : IDigest
    {
        public ASN1ObjectIdentifier Id => new ASN1ObjectIdentifier("1.2.840.113549.2.5");

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
