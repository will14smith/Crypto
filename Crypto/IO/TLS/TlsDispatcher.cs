using System;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class TlsDispatcher
    {
        private readonly TlsState state;

        public TlsDispatcher(TlsState state)
        {
            this.state = state;
        }

        public void AuthenticateAsServer()
        {
            state.SetMode(TlsMode.Server);

            while (true)
            {
                var record = state.RecordReader.ReadRecord();

                switch (record.Type)
                {
                    case RecordType.Handshake:
                        HandleHandshake(record);
                        break;
                    case RecordType.ChangeCipherSpec:
                        HandleChangeCipherSpec(record);
                        break;
                    default:
                        throw new NotImplementedException();
                }

                //TODO is this the correct check?
                if (state.ReadProtected && state.WriteProtected)
                {
                    return;
                }
            }
        }

        private void HandleHandshake(Record record)
        {
            var handshakeReader = new HandshakeReader(state);
            var handshakeWriter = new HandshakeWriter(state);

            var message = handshakeReader.Read(record);

            switch (message.Type)
            {
                case HandshakeType.ClientHello:
                    state.HandleClientHello((ClientHelloMessage)message);

                    var serverHellos = state.GenerateServerHello();
                    foreach (var hello in serverHellos)
                    {
                        handshakeWriter.Write(hello);
                    }

                    state.SentServerHello();

                    break;
                case HandshakeType.ClientKeyExchange:
                    state.HandleClientKeyExchange((ClientKeyExchangeMessage)message);
                    break;
                case HandshakeType.Finished:
                    HandleHandshakeFinished(message, handshakeWriter);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        private void HandleHandshakeFinished(HandshakeMessage message, HandshakeWriter handshakeWriter)
        {
            state.VerifyFinished((FinishedHandshakeMessage)message);
            if (state.Mode != TlsMode.Server)
            {
                return;
            }

            // send ChangeCipherSpec & Finished

            state.RecordWriter.WriteRecord(new Record(RecordType.ChangeCipherSpec, state.Version, new byte[] { 1 }));
            state.SentChangeCipherSpec();

            handshakeWriter.Write(state.GenerateFinishedMessage());
        }

        private void HandleChangeCipherSpec(Record record)
        {
            SecurityAssert.SAssert(record.Length == 1);
            SecurityAssert.SAssert(record.Data[0] == 1);

            state.ReceivedChangeCipherSpec();
        }
    }
}