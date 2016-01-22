using System;

namespace Crypto.IO.TLS
{
    internal static class KeyExchangeExtensions
    {
        public static bool RequiresCertificate(this KeyExchange keyExchange)
        {
            switch (keyExchange)
            {
                case KeyExchange.Null:
                case KeyExchange.DH_anon:
                    return false;

                case KeyExchange.RSA:
                case KeyExchange.DH_DSS:
                case KeyExchange.DH_RSA:
                case KeyExchange.DHE_DSS:
                case KeyExchange.DHE_RSA:
                    return true;

                default:
                    throw new ArgumentOutOfRangeException(nameof(keyExchange), keyExchange, null);
            }
        }

        public static bool RequiresKeyExchange(this KeyExchange keyExchange)
        {
            switch (keyExchange)
            {
                case KeyExchange.Null:
                case KeyExchange.RSA:
                case KeyExchange.DH_DSS:
                case KeyExchange.DH_RSA:
                    return false;

                case KeyExchange.DHE_DSS:
                case KeyExchange.DHE_RSA:
                case KeyExchange.DH_anon:
                    return true;

                default:
                    throw new ArgumentOutOfRangeException(nameof(keyExchange), keyExchange, null);
            }
        }
    }
}
