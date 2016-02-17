namespace Crypto.Encryption
{
    class RC4Cipher : ICipher
    {
        private readonly int keySize;

        public RC4Cipher(int keySize)
        {
            this.keySize = keySize;
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
