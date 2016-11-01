using System;
using System.Collections.Generic;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Extensions;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.EllipticCurve
{
    public class SupportedPointFormatsExtension : ITlsExtension
    {
        public static ushort HelloType => 0x000b;
        
        private readonly TlsState state;
        private readonly IReadOnlyList<byte> supportedFormats;

        public SupportedPointFormatsExtension(TlsState state, byte[] helloData)
        {
            this.state = state;

            SecurityAssert.SAssert(helloData.Length > 1);

            var length = helloData[0];
            SecurityAssert.SAssert(length > 0 && helloData.Length == length + 1);

            var list = new List<byte>();
            for (var i = 1; i < helloData.Length; i++)
            {
                list.Add(helloData[i]);
            }

            supportedFormats = list;
        }


        public HelloExtension GenerateHello()
        {
            if (state.ConnectionEnd == ConnectionEnd.Server)
            {
                // TODO actually determine this?
                // [1, 0] means: 1 item: 0 (uncompressed)
                return new HelloExtension(HelloType, new byte[] { 1, 0 });
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}