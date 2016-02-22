using Crypto.Encryption.Parameters;

namespace Crypto.Encryption
{
    public interface ICipher
    {
        int KeyLength { get; }

        void Init(ICipherParameters parameters);

        void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
        void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length);
    }

    public interface IBlockCipher
    {
        int BlockLength { get; }
        int KeyLength { get; }

        void Init(ICipherParameters parameters);

        void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
        void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
    }
}
