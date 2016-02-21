using System;
using Crypto.Encryption.Modes;
using Crypto.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Encryption
{
    public class BlockCipherAdapter : ICipher
    {
        public IBlockCipher BlockCipher { get; }

        public BlockCipherAdapter(IBlockCipher blockCipher)
        {
            BlockCipher = blockCipher;
        }

        public int KeyLength => BlockCipher.KeySize;
        public int BlockLength => BlockCipher.BlockLength;

        public void Init(ICipherParameters parameters)
        {
            BlockCipher.Init(parameters);
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityBufferAssert.AssertBuffer(input, inputOffset, length);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, length);

            for (var i = 0; i < length; i += BlockCipher.BlockLength)
            {
                BlockCipher.EncryptBlock(input, inputOffset + i, output, outputOffset + i);
            }
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityBufferAssert.AssertBuffer(input, inputOffset, length);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, length);

            for (var i = 0; i < length; i += BlockCipher.BlockLength)
            {
                BlockCipher.DecryptBlock(input, inputOffset + i, output, outputOffset + i);
            }
        }
    }
}
