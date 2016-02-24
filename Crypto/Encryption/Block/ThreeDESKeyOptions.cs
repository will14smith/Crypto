namespace Crypto.Encryption.Block
{
    public enum ThreeDESKeyOptions
    {
        // k1, k2, k3 are independant
        Option1,
        // k1 == k3
        Option2,
        // k1 == k2 == k3
        Option3,
    }
}
