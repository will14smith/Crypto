namespace Crypto.IO.TLS.Messages
{
    public class HandshakeWriter
    {
        private readonly TlsState state;

        public HandshakeWriter(TlsState state)
        {
            this.state = state;
        }

        public void Write(HandshakeMessage message)
        {
            var body = message.GetBytes();
            var record = new Record(RecordType.Handshake, state.Version, body);

            state.UpdateHandshakeVerify(body, 0, body.Length);
            state.RecordWriter.WriteRecord(record);
        }
    }
}
