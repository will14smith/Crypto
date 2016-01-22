namespace Crypto.Encryption
{
    class RC4Cipher : ICipher
    {
        private readonly int keySize;

        public RC4Cipher(int keySize)
        {
            this.keySize = keySize;
        }
    }
}
