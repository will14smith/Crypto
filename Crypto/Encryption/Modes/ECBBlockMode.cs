using System;

namespace Crypto.Encryption.Modes
{
    // ECB is just a NOP block mode
    public class ECBBlockMode : IBlockMode
    {
        public void Init(IBlockCipher cipher)
        {
        }

        public byte[] IV
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public void BeforeEncryption(byte[] input, int offset)
        {
        }

        public void AfterEncryption(byte[] input, int offset)
        {
        }

        public void BeforeDecryption(byte[] input, int offset)
        {
        }

        public void AfterDecryption(byte[] input, int offset)
        {
        }
    }
}
