using System;
using System.IO;
using Crypto.Utils;
using Crypto.Utils.IO;

namespace Crypto.IO.TLS.Messages
{
    public class HandshakeReader
    {
        private readonly TlsState state;

        internal HandshakeReader(TlsState state)
        {
            this.state = state;
        }

        public HandshakeMessage Read(Record record)
        {
            SecurityAssert.SAssert(record.Type == RecordType.Handshake);

            using (var ms = new MemoryStream(record.Data))
            {
                var msReader = new EndianBinaryReader(EndianBitConverter.Big, ms);

                var type = msReader.ReadHandshakeType();
                var length = msReader.ReadUInt24();

                if (record.Length - 4 < length) { throw new NotImplementedException("Record fragmentation"); }

                var body = msReader.ReadBytes((int)length);
                
                UpdateVerify(type, length, body);

                return Read(type, body);
            }
        }

        private void UpdateVerify(HandshakeType type, uint length, byte[] body)
        {
            if (type == HandshakeType.Finished)
            {
                state.ComputeHandshakeVerify();
            }

            state.UpdateHandshakeVerify(new[] {(byte) type}, 0, 1);
            state.UpdateHandshakeVerify(EndianBitConverter.Big.GetBytes(length), 1, 3);
            state.UpdateHandshakeVerify(body, 0, body.Length);
        }

        private HandshakeMessage Read(HandshakeType type, byte[] body)
        {
            switch (type)
            {
                case HandshakeType.ClientHello:
                    return ClientHelloMessage.Read(state, body);
                case HandshakeType.ClientKeyExchange:
                    return state.KeyExchange.ReadClientKeyExchange(body);
                case HandshakeType.Finished:
                    return FinishedHandshakeMessage.Read(state, body);

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
    }
}
