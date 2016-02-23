using System;
using System.Collections.Generic;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS.Extensions
{
    internal class SignatureAlgorithmExtensionConfiguration : TlsExtensionConfiguration
    {
        public override void Configure(TlsExtensionManager manager)
        {
            manager.RegisterHelloExtension(0x000d, Factory);
        }

        private static ITlsExtension Factory(TlsState state, byte[] helloData)
        {
            return new SignatureAlgorithmExtension(state, helloData);
        }
    }

    internal class SignatureAlgorithmExtension : ITlsExtension
    {
        private readonly TlsState state;
        private readonly List<Tuple<byte, byte>> algorithms = new List<Tuple<byte, byte>>();

        public SignatureAlgorithmExtension(TlsState state, byte[] helloData)
        {
            this.state = state;

            ReadData(helloData);
        }

        private void ReadData(byte[] data)
        {
            var length = EndianBitConverter.Big.ToUInt16(data, 0);
            SecurityAssert.SAssert(length % 2 == 0 && length >= 4);

            var count = length / 2;
            for (var i = 0; i < count; i++)
            {
                var hash = data[2 * i + 2];
                var sig = data[2 * i + 3];

                algorithms.Add(Tuple.Create(hash, sig));
            }
        }

        public HelloExtension GenerateHello()
        {
            if (state.ConnectionEnd == ConnectionEnd.Server)
            {
                return null;
            } 

            throw new NotImplementedException();
        }
    }
}
