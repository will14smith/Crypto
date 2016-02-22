using Crypto.Encryption.AEAD;
using Crypto.Encryption.Parameters;

namespace Crypto.Encryption
{
    public class AEADCipherAdapter : ICipher
    {
        public IAEADBlockCipher Cipher { get; }

        public AEADCipherAdapter(IAEADBlockCipher cipher)
        {
            this.Cipher = cipher;
        }

        public int KeySize => Cipher.KeySize;
        public int BlockLength => Cipher.BlockLength;
        public int TagLength => Cipher.TagLength;

        public void Init(ICipherParameters parameters)
        {
            Cipher.Init(parameters);
        }

        public void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            var offset = Cipher.Encrypt(input, inputOffset, output, outputOffset, length);
            Cipher.EncryptFinal(output, outputOffset + offset);
        }

        public void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            var offset = Cipher.Decrypt(input, inputOffset, output, outputOffset, length);
            Cipher.DecryptFinal(output, offset);
        }
    }
}
