namespace Crypto.IO.TLS
{
    public abstract class Record
    {
        protected Record(RecordType type, Version version, ushort length)
        {
            Type = type;
            Version = version;
            Length = length;
        }

        public RecordType Type { get; }
        public Version Version { get; }
        public ushort Length { get; }
    }
}
