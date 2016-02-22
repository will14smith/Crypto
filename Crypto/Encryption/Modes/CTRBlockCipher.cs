using System;
using Crypto.Utils;

namespace Crypto.Encryption.Modes
{
    public class CTRBlockCipher : IVBlockCipher
    {
        private byte[] counter;

        public CTRBlockCipher(IBlockCipher cipher) : base(cipher)
        {
        }

        protected override void Reset()
        {
            SecurityAssert.SAssert(IVInitialised);

            counter = new byte[BlockLength];
            Array.Copy(IV, 0, counter, 0, BlockLength);
        }

        public override void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            ProcessBlock(input, inputOffset, output, outputOffset);
        }

        public override void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            ProcessBlock(input, inputOffset, output, outputOffset);
        }

        private void ProcessBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            var counterOutput = new byte[BlockLength];
            Cipher.EncryptBlock(counter, 0, counterOutput, 0);

            // XOR input
            for (var i = 0; i < BlockLength; i++)
            {
                output[outputOffset + i] = (byte)(counterOutput[i] ^ input[inputOffset + i]);
            }

            // increment counter
            Inc();
        }

        public void Inc()
        {
            var j = BlockLength;
            while (j > 0 && ++counter[--j] == 0)
            {
            }
        }
    }
}
