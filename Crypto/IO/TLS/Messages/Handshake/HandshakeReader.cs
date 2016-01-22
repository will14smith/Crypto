﻿using System;
using System.IO;
using Crypto.Utils;

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

            var data = record.GetContents(state);

            using (var ms = new MemoryStream(data))
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

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
    }
}
