namespace Crypto.Encryption
{
    public interface ICipher
    {
        int BlockSize { get; }
        int KeySize { get; }

        void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
        void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
    }
}
