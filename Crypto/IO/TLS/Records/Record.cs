using Crypto.Utils;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// SENDING: unfragmented record
    /// RECIEVING fragmented record
    /// </summary>
    public class Record
    {
        public Record(RecordType type, TlsVersion version, byte[] data)
        {
            Type = type;
            Version = version;

            SecurityAssert.NotNull(data);
            Data = data;
        }

        public RecordType Type { get; }
        public TlsVersion Version { get; }
        public byte[] Data { get; }

        public int Length => Data.Length;
    }
}