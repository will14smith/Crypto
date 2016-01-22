namespace Crypto.IO.TLS
{
    public struct TlsVersion
    {
        public static readonly TlsVersion TLS1_2 = new TlsVersion(3, 3);

        public readonly int Major;
        public readonly int Minor;

        public TlsVersion(int major, int minor)
        {
            Major = major;
            Minor = minor;
        }
    }
}
