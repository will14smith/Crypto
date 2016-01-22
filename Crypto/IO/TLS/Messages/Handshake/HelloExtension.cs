using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages.Handshake
{
    public class HelloExtension
    {
        public HelloExtension(ushort type, byte[] data)
        {
            Type = type;

            SecurityAssert.NotNull(data);
            SecurityAssert.SAssert(data.Length >= 0 && data.Length <= 0xFFFF);
            Data = data;
        }

        public ushort Type { get; } 
        public byte[] Data { get; } 
    }
}
