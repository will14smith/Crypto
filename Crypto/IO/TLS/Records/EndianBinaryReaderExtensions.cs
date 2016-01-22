using Crypto.Utils.IO;

namespace Crypto.IO.TLS
{
    internal static class EndianBinaryReaderExtensions
    {
        public static RecordType ReadRecordType(this EndianBinaryReader reader)
        {
            return (RecordType)reader.ReadByte();
        }
        public static TlsVersion ReadVersion(this EndianBinaryReader reader)
        {
            var major = reader.ReadByte();
            var minor = reader.ReadByte();

            return new TlsVersion(major, minor);
        }
    }
}
