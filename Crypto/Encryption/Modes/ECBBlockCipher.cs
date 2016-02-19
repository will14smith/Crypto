using System;
using Crypto.Encryption.Parameters;

namespace Crypto.Encryption.Modes
{
    // ECB is just a NOP block mode
    public class ECBBlockCipher : IBlockCipher
    {
        public IBlockCipher Cipher { get; }

        public ECBBlockCipher(IBlockCipher cipher)
        {
            Cipher = cipher;
        }

        public int BlockSize => Cipher.BlockSize;
        public int KeySize => Cipher.KeySize;

        public void Init(ICipherParameters parameters)
        {
            Cipher.Init(parameters);
        }

        public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            Cipher.EncryptBlock(input, inputOffset, output, outputOffset);
        }

        public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            Cipher.DecryptBlock(input, inputOffset, output, outputOffset);
        }
    }
}
