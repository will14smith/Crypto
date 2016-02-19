using System;
using Crypto.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Encryption.Modes
{
    public class CBCBlockCipher : IBlockCipher
    {
        public IBlockCipher Cipher { get; }

        private bool ivInitialised;
        private readonly byte[] iv;

        private byte[] workingIV;

        public CBCBlockCipher(IBlockCipher cipher)
        {
            Cipher = cipher;

            iv = new byte[BlockSize];
        }

        public int BlockSize => Cipher.BlockSize;
        public int KeySize => Cipher.KeySize;

        public void Init(ICipherParameters parameters)
        {
            var ivParams = parameters as IVParameter;
            if (ivParams == null)
            {
                Cipher.Init(parameters);
                return;
            }

            var ivParam = ivParams.IV;
            SecurityAssert.NotNull(ivParam);
            SecurityAssert.SAssert(ivParam.Length == BlockSize);

            Array.Copy(ivParam, iv, BlockSize);
            ivInitialised = true;

            if (ivParams.Parameters != null)
            {
                Cipher.Init(ivParams.Parameters);
            }

            Reset();
        }

        private void Reset()
        {
            SecurityAssert.SAssert(ivInitialised);

            workingIV = new byte[BlockSize];
            Array.Copy(iv, workingIV, BlockSize);
        }

        public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.SAssert(ivInitialised);
            SecurityBufferAssert.AssertBuffer(input, inputOffset, BlockSize);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, BlockSize);

            var tmp = new byte[BlockSize];
            Array.Copy(input, inputOffset, tmp, 0, BlockSize);

            BufferUtils.Xor(workingIV, 0, tmp, 0, BlockSize);

            Cipher.EncryptBlock(tmp, 0, output, outputOffset);

            Array.Copy(output, outputOffset, workingIV, 0, BlockSize);
        }

        public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.SAssert(ivInitialised);
            SecurityBufferAssert.AssertBuffer(input, inputOffset, BlockSize);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, BlockSize);

            Cipher.DecryptBlock(input, inputOffset, output, outputOffset);

            BufferUtils.Xor(workingIV, 0, output, outputOffset, BlockSize);
            Array.Copy(input, inputOffset, workingIV, 0, BlockSize);
        }
    }
}
