using Crypto.ASN1;

namespace Crypto.Hashing
{
    public interface IDigest
    {
        ASN1ObjectIdentifier Id { get; }

        void Update(byte[] buffer, int offset, int length);
        byte[] Digest();
    }
}
