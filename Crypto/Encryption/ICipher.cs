namespace Crypto.Encryption
{
    public interface ICipher
    {
        void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
        void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
    }
    public interface IBlockCipher
    {
        int BlockSize { get; }
        int KeySize { get; }

        void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
        void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
    }
}
