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
    }
}
