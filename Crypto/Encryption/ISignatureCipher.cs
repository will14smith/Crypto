using Crypto.Hashing;

namespace Crypto.Encryption
{
    public interface ISignatureCipher
    {
        byte[] Sign(byte[] input, IDigest hash);
        bool Verify(byte[] input, byte[] signature, IDigest hash);
    }
}
