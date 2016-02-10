﻿using System;
using System.Collections.Generic;
using System.Numerics;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    class DHEKeyExchange : KeyExchange
    {
        public static readonly string ParamP = "DHE_p";
        public static readonly string ParamG = "DHE_g";
        public static readonly string ParamX = "DHE_X";

        private TlsState state;
        private readonly KeyExchange innerKeyExchange;

        public DHEKeyExchange(KeyExchange innerKeyExchange)
        {
            SecurityAssert.NotNull(innerKeyExchange);
            SecurityAssert.SAssert(innerKeyExchange.RequiresCertificate && !innerKeyExchange.RequiresKeyExchange);

            this.innerKeyExchange = innerKeyExchange;
        }

        public bool RequiresCertificate => innerKeyExchange.RequiresCertificate;
        public bool RequiresKeyExchange => true;

        public void Init(TlsState state)
        {
            this.state = state;
            innerKeyExchange.Init(state);

            // TODO find a decent source for sizes...

            // 2048-bit (prime)
            // var p = RandomGenerator.RandomPrime(2048);
            //TODO allow external specifcation of this (or generate if not)
            var p = new BigInteger(Convert.FromBase64String("tU9bHsPUA77Tfndcz3qNV91mXBOU34MynSkioJqdOjehwulssAYMJS5vFv4ulCKSnM+jGPiZT9XLKYGasmMjNUQ/uw2QIKfWWjbkJMiFAwkGjwPL+iE/B3IUoYaFcXPKS+C67tkUAnsnzL7BtCoMRiV4kyNgWDsiALOae38gUejDGdnoyxUv8Y2Hoy1jfVNICFtgDd5PavKll+0leob8B3vW/ZpQJHsQSKGW2bUNv4NgUXMkv0QJc6/mQjMnCncGi5yyjX+49+PgUMQ9uZE9mNhqxCkS10c3zIrrauFH6D0qj00YWjIEqFqQRG5/zLoeqKlbvUZO87NUe8D1zI0BmAA="));
            // static generator
            var g = new BigInteger(2);
            // 256-bit (server secret)
            var x = RandomGenerator.RandomBig(256);

            state.Params.Add(ParamP, p);
            state.Params.Add(ParamG, g);
            state.Params.Add(ParamX, x);
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            foreach (var message in innerKeyExchange.GenerateHandshakeMessages())
            {
                yield return message;
            }

            var p = state.Params[ParamP];
            var g = state.Params[ParamG];
            var x = state.Params[ParamX];

            var Ys = BigInteger.ModPow(g, x, p);

            yield return new SignedKeyExchangeMessage(state, p, g, Ys);
        }

        public HandshakeMessage ReadClientKeyExchange(byte[] body)
        {
            var length = EndianBitConverter.Big.ToUInt16(body, 0);
            SecurityAssert.SAssert(body.Length == length + 2);

            var param = new byte[length];
            Array.Copy(param, 0, body, 2, length);

            return new ClientKeyExchangeMessage.DH(param);
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            var dhMessage = message as ClientKeyExchangeMessage.DH;
            SecurityAssert.NotNull(dhMessage);

            var p = state.Params[ParamP];
            var x = state.Params[ParamX];
            var Yc = dhMessage.Yc;

            var Z = BigInteger.ModPow(Yc, x, p);
            var preMasterSecret = Z.ToTlsBytes();

        }
    }
}
