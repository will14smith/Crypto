using Crypto.Encryption.Parameters;

namespace Crypto.Encryption.AEAD
{
    public interface IAEADBlockCipher
    {
        int BlockLength { get; }
        int KeySize { get; }
        int TagLength { get; }

        void Init(ICipherParameters parameters);

        //TODO other functions...

        int Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
        int EncryptFinal(byte[] output, int offset);

        int Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
        int DecryptFinal(byte[] output, int offset);
    }
}