namespace Crypto.Encryption
{
    class ThreeDESCipher : IBlockCipher
    {
        private readonly ThreeDESKeyOptions keyMode;

        public ThreeDESCipher(ThreeDESKeyOptions keyMode)
        {
            this.keyMode = keyMode;
        }

        public int BlockSize { get; }
        public int KeySize { get; }
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
