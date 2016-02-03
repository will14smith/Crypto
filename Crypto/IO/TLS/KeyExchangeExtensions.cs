//using System;
//using Crypto.IO.TLS.Messages;
//using Crypto.Utils;

//namespace Crypto.IO.TLS
//{
//    internal static class KeyExchangeExtensions
//    {
//        public static bool RequiresCertificate(this KeyExchange keyExchange)
//        {
//            switch (keyExchange)
//            {
//                case KeyExchange.Null:
//                case KeyExchange.DH_anon:
//                    return false;

//                case KeyExchange.RSA:
//                case KeyExchange.DH_DSS:
//                case KeyExchange.DH_RSA:
//                case KeyExchange.DHE_DSS:
//                case KeyExchange.DHE_RSA:
//                    return true;

//                default:
//                    throw new ArgumentOutOfRangeException(nameof(keyExchange), keyExchange, null);
//            }
//        }

//        public static bool RequiresKeyExchange(this KeyExchange keyExchange)
//        {
//            switch (keyExchange)
//            {
//                case KeyExchange.Null:
//                case KeyExchange.RSA:
//                case KeyExchange.DH_DSS:
//                case KeyExchange.DH_RSA:
//                    return false;

//                case KeyExchange.DHE_DSS:
//                case KeyExchange.DHE_RSA:
//                case KeyExchange.DH_anon:
//                    return true;

//                default:
//                    throw new ArgumentOutOfRangeException(nameof(keyExchange), keyExchange, null);
//            }
//        }

//        public static HandshakeMessage SetupKeyExchange(this KeyExchange keyExchange, TlsState state)
//        {
//            SecurityAssert.SAssert(keyExchange.RequiresKeyExchange());

//            if (keyExchange == KeyExchange.DH_anon)
//            {
//                // ServerDHParams params;
//            }
//            else if (keyExchange == KeyExchange.DHE_DSS || keyExchange == KeyExchange.DHE_RSA)
//            {
//                // ServerDHParams params;
//                // digitally-signed struct {
//                //   opaque client_random[32];
//                //   opaque server_random[32];
//                //   ServerDHParams params;
//                // } signed_params;
//            }

//            throw new NotImplementedException();
//        }
//    }
//}
