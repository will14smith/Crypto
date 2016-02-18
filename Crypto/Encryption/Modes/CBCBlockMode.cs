using System;

namespace Crypto.Encryption.Modes
{
    public class CBCBlockMode : IBlockMode
    {
        private int blockSize;

        public void Init(IBlockCipher cipher)
        {
            blockSize = cipher.BlockSize;

            if (IV == null)
            {
                IV = RandomGenerator.RandomBytes(blockSize);
            }
            else if (IV.Length != blockSize)
            {
                throw new InvalidOperationException("IV length doesn't match block size");
            }
        }

        public byte[] IV { get; set; }
        private byte[] previousIV;

        public void BeforeEncryption(byte[] input, int offset)
        {
            throw new NotImplementedException();
        }

        public void AfterEncryption(byte[] input, int offset)
        {
            throw new NotImplementedException();
        }

        public void BeforeDecryption(byte[] input, int offset)
        {
            previousIV = new byte[blockSize];
            Array.Copy(input, offset, previousIV, 0, blockSize);
        }

        public void AfterDecryption(byte[] input, int offset)
        {
            for (var i = 0; i < blockSize; i++)
            {
                input[i + offset] ^= IV[i];
            }

            IV = previousIV;
        }
    }
}
