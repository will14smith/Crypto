using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    class DHEKeyExchange : KeyExchange
    {
        public static readonly string PARAM_P = "DHE_p";
        public static readonly string PARAM_G = "DHE_g";
        public static readonly string PARAM_X = "DHE_X";

        private readonly KeyExchange innerKeyExchange;

        public DHEKeyExchange(KeyExchange innerKeyExchange)
        {
            SecurityAssert.NotNull(innerKeyExchange);
            SecurityAssert.SAssert(innerKeyExchange.RequiresCertificate && !innerKeyExchange.RequiresKeyExchange);

            this.innerKeyExchange = innerKeyExchange;
        }

        public override bool RequiresCertificate => innerKeyExchange.RequiresCertificate;
        public override bool RequiresKeyExchange => true;

        internal override void InitialiseState(TlsState state)
        {
            innerKeyExchange.InitialiseState(state);

            // TODO find a decent source for sizes...
            // TODO generate random numbers

            // 2048-bit
            var p = BigInteger.One;
            // 256-bit
            var g = BigInteger.One;
            // 256-bit
            var x = BigInteger.One;

            state.Params.Add(PARAM_P, p);
            state.Params.Add(PARAM_G, g);
            state.Params.Add(PARAM_X, x);
        }

        internal override IEnumerable<HandshakeMessage> GenerateHandshakeMessages(TlsState state)
        {
            foreach (var message in innerKeyExchange.GenerateHandshakeMessages(state))
            {
                yield return message;
            }

            // TODO yield key exchange message

            var p = state.Params[PARAM_P];
            var g = state.Params[PARAM_P];
            var x = state.Params[PARAM_X];

            var Ys = (g ^ x) % p;

            yield return new SignedKeyExchangeMessage(state, p, g, Ys);
        }
    }
}
