namespace Crypto.Hashing
{
    public interface IDigest
    {
        void Update(byte[] buffer, int offset, int length);
        byte[] Digest();
    }
}
