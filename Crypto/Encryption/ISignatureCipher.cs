namespace Crypto.Encryption
{
    public interface ISignatureCipher
    {
        byte[] Sign(byte[] input);
        bool Verify(byte[] sig);
    }
}
