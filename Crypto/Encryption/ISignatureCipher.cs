using Crypto.Encryption.Parameters;
using Crypto.Hashing;

namespace Crypto.Encryption
{
    public interface ISignatureCipher
    {
        void Init(ICipherParameters parameters);

        byte[] Sign(byte[] input, IDigest hash);
        bool Verify(byte[] input, byte[] signature, IDigest hash);
    }
}
