using Crypto.Encryption.Parameters;

namespace Crypto.Encryption.Block
{
    public class ThreeDESCipher : IBlockCipher
    {
        private readonly ThreeDESKeyOptions keyMode;

        public ThreeDESCipher(ThreeDESKeyOptions keyMode)
        {
            this.keyMode = keyMode;
        }

        public int BlockLength { get; }
        public int KeyLength { get; }
        public void Init(ICipherParameters parameters)
        {
            throw new System.NotImplementedException();
        }

        public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            throw new System.NotImplementedException();
        }

        public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            throw new System.NotImplementedException();
        }
    }
}
