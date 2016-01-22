namespace Crypto.IO.TLS.Messages
{
    internal class HandshakeWriter
    {
        private readonly TlsState state;
        private readonly RecordWriter writer;

        public HandshakeWriter(TlsState state)
        {
            this.state = state;
            writer = state.GetRecordWriter();
        }

        public void Write(HandshakeMessage message)
        {
            var body = message.GetBytes();
            var record = new Record(RecordType.Handshake, state.Version, body);

            writer.WriteRecord(record);
        }
    }
}
