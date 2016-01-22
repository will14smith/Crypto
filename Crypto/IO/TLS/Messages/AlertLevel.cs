using System;

namespace Crypto.IO.TLS.Messages
{
    [Flags]
    public enum AlertLevel : byte
    {
        Warning = 1,
        Fatal = 2,
    }
}