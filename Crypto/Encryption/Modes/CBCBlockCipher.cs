using System;
using Crypto.Utils;

namespace Crypto.Encryption.Modes
{
    public class CBCBlockCipher : IVBlockCipher
    {
        private byte[] workingIV;

        public CBCBlockCipher(IBlockCipher cipher) : base(cipher)
        {
        }

        protected override void Reset()
        {
            SecurityAssert.SAssert(IVInitialised);

            workingIV = new byte[BlockLength];
            Array.Copy(IV, workingIV, BlockLength);
        }

        public override void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.SAssert(IVInitialised);
            SecurityBufferAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, BlockLength);

            var tmp = new byte[BlockLength];
            Array.Copy(input, inputOffset, tmp, 0, BlockLength);

            BufferUtils.Xor(workingIV, 0, tmp, 0, BlockLength);

            Cipher.EncryptBlock(tmp, 0, output, outputOffset);

            Array.Copy(output, outputOffset, workingIV, 0, BlockLength);
        }

        public override void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityAssert.SAssert(IVInitialised);
            SecurityBufferAssert.AssertBuffer(input, inputOffset, BlockLength);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, BlockLength);

            Cipher.DecryptBlock(input, inputOffset, output, outputOffset);

            BufferUtils.Xor(workingIV, 0, output, outputOffset, BlockLength);
            Array.Copy(input, inputOffset, workingIV, 0, BlockLength);
        }
    }
}
