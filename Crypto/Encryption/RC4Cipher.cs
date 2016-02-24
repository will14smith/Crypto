using Crypto.Encryption.Parameters;

namespace Crypto.Encryption
{
    public class RC4Cipher : ICipher
    {
        private readonly int keySize;

        public RC4Cipher(int keySize)
        {
            this.keySize = keySize;
        }

        public int KeySize { get; }

        public void Init(ICipherParameters parameters)
        {
            throw new System.NotImplementedException();
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            throw new System.NotImplementedException();
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            throw new System.NotImplementedException();
        }
    }
}
