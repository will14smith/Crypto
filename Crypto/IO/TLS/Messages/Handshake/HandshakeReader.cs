using System;
using System.IO;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public class HandshakeReader
    {
        private readonly TlsState state;
        private readonly RecordReader reader;

        internal HandshakeReader(TlsState state)
        {
            this.state = state;
            reader = state.GetRecordReader();
        }

        public HandshakeMessage Read()
        {
            var record = reader.ReadRecord();

            SecurityAssert.SAssert(record.Type == RecordType.Handshake);

            using (var ms = new MemoryStream(record.Data))
            {
                var msReader = new EndianBinaryReader(EndianBitConverter.Big, ms);

                var type = msReader.ReadHandshakeType();
                var length = msReader.ReadUInt24();

                if(record.Length - 4 < length) { throw new NotImplementedException("Record fragmentation"); }

                var body = msReader.ReadBytes((int)length);

                return Read(type, body);
            }
        }

        private HandshakeMessage Read(HandshakeType type, byte[] body)
        {
            switch (type)
            {
                case HandshakeType.ClientHello:
                    return ClientHelloMessage.Read(state, body);
                case HandshakeType.ClientKeyExchange:
                    return state.KeyExchange.ReadClientKeyExchange(body);

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
    }
}
