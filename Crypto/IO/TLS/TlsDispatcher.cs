using System;
using System.Collections.Generic;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class TlsDispatcher
    {
        private readonly TlsState state;
        private Queue<byte> applicationBuffer = new Queue<byte>();

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

                HandleRecord(record);

                //TODO is this the correct check?
                if (state.ReadProtected && state.WriteProtected)
                {
                    return;
                }
            }
        }

        public int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            while (applicationBuffer.Count == 0)
            {
                var record = state.RecordReader.ReadRecord();

                HandleRecord(record);
            }

            var length = Math.Min(count, applicationBuffer.Count);

            for (var i = 0; i < length; i++)
            {
                buffer[offset + i] = applicationBuffer.Dequeue();
            }

            return length;
        }

        public void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        private void HandleRecord(Record record)
        {
            switch (record.Type)
            {
                case RecordType.Handshake:
                    HandleHandshake(record);
                    break;
                case RecordType.ChangeCipherSpec:
                    HandleChangeCipherSpec(record);
                    break;
                case RecordType.Application:
                    HandleAppliction(record);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        private void HandleAppliction(Record record)
        {
            foreach (var b in record.Data)
            {
                applicationBuffer.Enqueue(b);
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