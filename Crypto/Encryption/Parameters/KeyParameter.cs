using System;
using Crypto.Utils;

namespace Crypto.Encryption.Parameters
{
    public class KeyParameter : ICipherParameters
    {
        public KeyParameter(byte[] key)
        {
            SecurityAssert.NotNull(key);

            Key = new byte[key.Length];
            Array.Copy(key, Key, key.Length);
        }
        public KeyParameter(byte[] key, int offset, int length)
        {
            SecurityBufferAssert.AssertBuffer(key, offset, length);

            Key = new byte[length];
            Array.Copy(key, offset, Key, 0, length);
        }

        public byte[] Key { get; }
    }
}
