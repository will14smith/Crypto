namespace Crypto.Encryption
{
    class ThreeDESCipher : ICipher
    {
        private readonly ThreeDESKeyOptions keyMode;
        private readonly CipherBlockMode blockMode;

        public ThreeDESCipher(ThreeDESKeyOptions keyMode, CipherBlockMode blockMode)
        {
            this.keyMode = keyMode;
            this.blockMode = blockMode;
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
