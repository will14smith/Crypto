using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.Encryption
{
    class AESCipher : ICipher
    {
        private readonly int keySize;
        private readonly CipherBlockMode blockMode;

        public AESCipher(int keySize, CipherBlockMode blockMode)
        {
            this.keySize = keySize;
            this.blockMode = blockMode;
        }
    }
}
