namespace Crypto.IO.TLS
{
    internal static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, RecordType type)
        {
            writer.Write((byte)type);
        }
        public static void Write(this EndianBinaryWriter writer, TlsVersion version)
        {
            writer.Write(version.Major);
            writer.Write(version.Minor);
        }
    }
}