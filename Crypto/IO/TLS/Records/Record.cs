namespace Crypto.IO.TLS
{
    public abstract class Record
    {
        protected Record(RecordType type, TlsVersion version, ushort length)
        {
            Type = type;
            Version = version;
            Length = length;
        }

        public RecordType Type { get; }
        public TlsVersion Version { get; }
        public ushort Length { get; }

        internal abstract byte[] GetContents(TlsState state);
    }
}
