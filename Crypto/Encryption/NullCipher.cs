using System;
using Crypto.Encryption.Parameters;
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

        public int KeySize { get; }

        public void Init(ICipherParameters parameters)
        {
            throw new NotImplementedException();
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            throw new System.NotImplementedException();
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            throw new System.NotImplementedException();
        }
    }
}
