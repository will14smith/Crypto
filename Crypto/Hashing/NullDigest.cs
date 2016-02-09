using System;
using Crypto.ASN1;

namespace Crypto.Hashing
{
    class NullDigest : IDigest
    {
        public ASN1ObjectIdentifier Id => null;

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
