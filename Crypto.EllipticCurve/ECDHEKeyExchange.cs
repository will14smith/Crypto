using System;
using System.Collections.Generic;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Messages;
using Crypto.Utils.IO;

namespace Crypto.EllipticCurve
{
    public class ECDHEKeyExchange : ITlsKeyExchange
    {
        private TlsState state;
        private readonly RSAKeyExchange innerExchange;

        public ECDHEKeyExchange()
        {
            innerExchange = new RSAKeyExchange();
        }

        public void Init(TlsState state)
        {
            this.state = state;
            innerExchange.Init(state);
            //TODO ensure certificate is compatible
        }

        public IEnumerable<HandshakeMessage> GenerateHandshakeMessages()
        {
            foreach (var message in innerExchange.GenerateHandshakeMessages())
            {
                yield return message;
            }

            // select curve
            // select point format
            // TODO ECDHE...


            // enum { explicit_prime (1), explicit_char2 (2), named_curve(3), reserved(248..255) } ECCurveType;
            // enum { ec_basis_trinomial, ec_basis_pentanomial } ECBasisType;

            // struct {
            //      opaque a <1..2^8-1>;
            //      opaque b <1..2^8-1>;
            // } ECCurve;

            // struct {
            //      opaque point <1..2^8-1>;
            // } ECPoint;

            // struct {
            //      ECCurveType curve_type;
            //      select(curve_type)
            //      {
            //          case explicit_prime:
            //              opaque prime_p <1..2^8-1>;
            //              ECCurve curve;
            //              ECPoint base;
            //              opaque order <1..2^8-1>;
            //              opaque cofactor <1..2^8-1>;
            //          case explicit_char2:
            //              uint16 m;
            //              ECBasisType basis;
            //              select(basis) {
            //                  case ec_trinomial:
            //                      opaque k <1..2^8-1>;
            //                  case ec_pentanomial:
            //                      opaque k1 <1..2^8-1>;
            //                      opaque k2 <1..2^8-1>;
            //                      opaque k3 <1..2^8-1>;
            //              };
            //              ECCurve curve;
            //              ECPoint base;
            //              opaque order <1..2^8-1>;
            //              opaque cofactor <1..2^8-1>;
            //          case named_curve:
            //              NamedCurve namedcurve;
            //      };
            // } ECParameters;


            // ECParameters curve_params
            // ECPoint public

            yield return new ECDHServerKeyExchangeMessage();
        }

        public HandshakeMessage ReadClientKeyExchange(byte[] body)
        {
            throw new NotImplementedException();
        }

        public void HandleClientKeyExchange(ClientKeyExchangeMessage message)
        {
            throw new NotImplementedException();
        }
    }

    public class ECDHServerKeyExchangeMessage : HandshakeMessage
    {
        public ECDHServerKeyExchangeMessage() : base(HandshakeType.ServerKeyExchange)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}