namespace Crypto.IO.TLS
{
    public struct Version
    {
        public static readonly Version TLS1_2 = new Version(3, 3);

        public readonly int Major;
        public readonly int Minor;

        public Version(int major, int minor)
        {
            Major = major;
            Minor = minor;
        }
    }
}
