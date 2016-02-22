using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.Encryption.Parameters;
using Crypto.Utils;

namespace Crypto.Encryption.Modes
{
    public abstract class IVBlockCipher : IBlockCipher
    {
        public IBlockCipher Cipher { get; }

        protected bool IVInitialised { get; private set; }
        protected byte[] IV { get; }

        protected IVBlockCipher(IBlockCipher cipher)
        {
            Cipher = cipher;

            IV = new byte[BlockLength];
        }

        public int BlockLength => Cipher.BlockLength;
        public int KeyLength => Cipher.KeyLength;

        public virtual void Init(ICipherParameters parameters)
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

            Array.Copy(ivParam, IV, BlockLength);
            IVInitialised = true;

            if (ivParams.Parameters != null)
            {
                Cipher.Init(ivParams.Parameters);
            }

            Reset();
        }

        protected abstract void Reset();

        public abstract void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
        public abstract void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
    }
}
