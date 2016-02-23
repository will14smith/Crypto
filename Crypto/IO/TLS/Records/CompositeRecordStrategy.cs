namespace Crypto.IO.TLS
{
    internal class CompositeRecordStrategy : IRecordStrategy
    {
        public CompositeRecordStrategy(RecordStrategy readStrategy, RecordStrategy writeStrategy)
        {
            ReadStrategy = readStrategy;
            WriteStrategy = writeStrategy;
        }

        public RecordStrategy ReadStrategy { get; }
        public RecordStrategy WriteStrategy { get; }
        
        public Record Read(RecordType type, TlsVersion version, ushort length)
        {
            return ReadStrategy.Read(type, version, length);
        }

        public void Write(RecordType type, TlsVersion version, byte[] data)
        {
            WriteStrategy.Write(type, version, data);
        }
    }
}
