using System;
using Crypto.Hashing;

namespace Crypto.Encryption
{
    class NullCipher : ICipher, ISignatureCipher
    {
        public byte[] Sign(byte[] input, IDigest hash)
        {
            throw new NotImplementedException();
        }

        public bool Verify(byte[] input, byte[] signature, IDigest hash)
        {
            throw new NotImplementedException();
        }

        public int BlockSize { get; }
        public int KeySize { get; }
        public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            throw new NotImplementedException();
        }
    }
}
