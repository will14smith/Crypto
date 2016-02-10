using Crypto.ASN1;

namespace Crypto.Hashing
{
    public interface IDigest
    {
        ASN1ObjectIdentifier Id { get; }

        int BlockSize { get; }
        int HashSize { get; }

        void Update(byte[] buffer, int offset, int length);
        byte[] Digest();

        void Reset();
    }
}
