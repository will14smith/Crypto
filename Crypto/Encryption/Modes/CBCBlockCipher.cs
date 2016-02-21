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

            iv = new byte[BlockLength];
        }

        public int BlockLength => Cipher.BlockLength;
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
            SecurityAssert.SAssert(ivParam.Length == BlockLength);

            Array.Copy(ivParam, iv, BlockLength);
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

            workingIV = new byte[BlockLength];
            Array.Copy(iv, workingIV, BlockLength);
        }

        public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.SAssert(ivInitialised);
            SecurityBufferAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, BlockLength);

            var tmp = new byte[BlockLength];
            Array.Copy(input, inputOffset, tmp, 0, BlockLength);

            BufferUtils.Xor(workingIV, 0, tmp, 0, BlockLength);

            Cipher.EncryptBlock(tmp, 0, output, outputOffset);

            Array.Copy(output, outputOffset, workingIV, 0, BlockLength);
        }

        public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.SAssert(ivInitialised);
            SecurityBufferAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, BlockLength);

            Cipher.DecryptBlock(input, inputOffset, output, outputOffset);

            BufferUtils.Xor(workingIV, 0, output, outputOffset, BlockLength);
            Array.Copy(input, inputOffset, workingIV, 0, BlockLength);
        }
    }
}
