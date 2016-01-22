namespace Crypto.IO.TLS
{
    public struct TlsVersion
    {
        public static readonly TlsVersion TLS1_2 = new TlsVersion(3, 3);

        public readonly byte Major;
        public readonly byte Minor;

        public TlsVersion(byte major, byte minor)
        {
            Major = major;
            Minor = minor;
        }
    }
}
