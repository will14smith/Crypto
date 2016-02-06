using System;

namespace Crypto.Hashing
{
    class NullDigest : IDigest
    {
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
