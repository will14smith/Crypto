using System;
using Crypto.Utils;

namespace Crypto.Encryption.Modes
{
    public class BlockModeCipher : ICipher
    {
        public IBlockCipher Cipher { get; }
        public IBlockMode Mode { get; }

        public BlockModeCipher(IBlockCipher cipher, IBlockMode mode)
        {
            Cipher = cipher;
            Mode = mode;
        }


        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.NotNull(input);
            SecurityAssert.SAssert(inputOffset + length <= input.Length);
            SecurityAssert.NotNull(output);
            SecurityAssert.SAssert(outputOffset + length <= output.Length);

            var blockSize = Cipher.BlockSize;
        
            // TODO this can probably be relaxed (ECB & CBC will need padding scheme)
            SecurityAssert.SAssert(length % blockSize == 0);

            Mode.Init(Cipher);

            var work = new byte[blockSize];
            for (var i = 0; i < length; i += blockSize)
            {
                Array.Copy(input, inputOffset + i, work, 0, blockSize);

                Mode.BeforeEncryption(work, 0);
                Cipher.EncryptBlock(work, 0, output, outputOffset);
                Mode.AfterEncryption(output, 0);
            }
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            SecurityAssert.NotNull(input);
            SecurityAssert.SAssert(inputOffset + length <= input.Length);
            SecurityAssert.NotNull(output);
            SecurityAssert.SAssert(outputOffset + length <= output.Length);

            var blockSize = Cipher.BlockSize;
            SecurityAssert.SAssert(length % blockSize == 0);

            Mode.Init(Cipher);

            var work = new byte[blockSize];
            for (var i = 0; i < length; i += blockSize)
            {
                Array.Copy(input, inputOffset + i, work, 0, blockSize);

                Mode.BeforeDecryption(work, 0);
                Cipher.EncryptBlock(work, 0, output, outputOffset);
                Mode.AfterDecryption(output, 0);
            }
        }
    }
}
