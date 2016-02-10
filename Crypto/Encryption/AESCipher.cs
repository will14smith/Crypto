using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.Utils;

namespace Crypto.Encryption
{
    class AESCipher : ICipher
    {
        private readonly int BLOCK_SIZE = 16;

        private readonly int keySize;
        private readonly CipherBlockMode blockMode;

        private readonly byte[] key;
        private readonly byte[] iv = new byte[16];

        public AESCipher(int keySize, CipherBlockMode blockMode)
        {
            SecurityAssert.SAssert(keySize == 128 || keySize == 192 || keySize == 256);

            this.keySize = keySize / 8;
            this.blockMode = blockMode;

            key = new byte[this.keySize];
        }

        public byte[] Key
        {
            set
            {
                SecurityAssert.NotNull(value);
                SecurityAssert.SAssert(value.Length == keySize);
                Array.Copy(value, key, keySize);
            }
        }

        public byte[] IV
        {
            set
            {
                SecurityAssert.NotNull(value);
                SecurityAssert.SAssert(value.Length == 16);
                Array.Copy(value, iv, keySize);
            }
        }
    }
}
