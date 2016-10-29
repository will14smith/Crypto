using System;
using System.Collections.Generic;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Extensions;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.EllipticCurve
{
    public class SupportedGroupsExtension : ITlsExtension
    {
        public static ushort HelloType => 0x000a;

        private readonly TlsState state;
        private readonly IReadOnlyList<ushort> supportedGroups;

        public SupportedGroupsExtension(TlsState state, byte[] helloData)
        {
            this.state = state;

            SecurityAssert.SAssert(helloData.Length > 2);
            var length = EndianBitConverter.Big.ToUInt16(helloData, 0);
            SecurityAssert.SAssert(length > 1 && helloData.Length == length + 2);

            var list = new List<ushort>();
            for (var i = 2; i < helloData.Length; i += 2)
            {
                list.Add(EndianBitConverter.Big.ToUInt16(helloData, i));
            }

            supportedGroups = list;
        }

        public HelloExtension GenerateHello()
        {
            if (state.ConnectionEnd == ConnectionEnd.Server)
            {
                return null;
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}