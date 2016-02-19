using System.IO;
using System.Linq;
using System.Numerics;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.IO.TLS
{
    [TestClass]
    public class DHEKeyExchangeTests
    {
        [TestMethod]
        public void NISTVectorsTest()
        {
            var p = "ca60d25245efbba8c7f61d2344fd692aa42df7842b83131ad8e6afd94f51adf01fc79a5db87ce2f7c2235fec416ae9d1268e1827b179a3602add735d167d6034cc4f6e33671e6e68bb5340ffc7e8172ed183881d20f773e271ff5db5524bdc3b8bf3ea9e505c993c7879b2c3575c25e0c66800266998ec45a0f8fcfb44884d07156ae63b5be321944453a5c425612a6d76d44fda03530423ffe08245a86702f6b9d7bc87103c4094d9cbb2a69a6560386f025cea444c2779a576efdfbe470209d091609c29a3321402993f820a67de6044a9a3eae9c11d882de1c19a8dd8f8bdc4193c432826cac60bed5e691b441a4c6995d1fe3117a9418777e767afdcdeff";
            var g = "758d43fb520121e1ad3d6af76e9e84da1057741594d14ca75d6ca296217df11f62db8703f3e212c8bbd381a961a83815f41e4135c068d27417d320acce6285393d8c456bf1298c29545426ede51ae129063159c9467ae7fea75864863a4b2d01feaf6e3da76caf62cfdb5d63751a6188f31b1191f46c0dd141079b16cf545d7c8db633759295efeb4357f8c7bb23006b5f541eb8b7d16f8d43d65b69455e159727fa281cd80a01c4376922a2f0ddd3e1f61f42297a212f9f27fde0ded87974eb63eb1bf3f65986bce9868a88590196779f95e00a87bb271ab159e09c2596ae58e507ab285a0b0b1cf67aac8c31d51bf8da4d0ef99c7e9d5d7cfb765f75cc0a63";

            var serverPriv = "901729dff82c5cfff88714e327ea3ecc91b196697c4a214fee614222";
            var serverPub = "8be42d22a595c7e00c96a17e13976c91fd8da0b9a67ffc5f76295c07df05153d6c4ee14ce3731f290f3aa06bdd35e2d5e069227a2eea34cb0e7c83d9458a9b904f84ef08cab7281ae68a17f18e2a183241b6f4dd7eba7ee2b1b27279ea38c68570d9747020d111d55963a1680a870bd92637abd24e1050d96584823a7e22ef675e54027d20bcd71ecab5d2093e4001f861226b398563a00b88d1dbfcba12315b9285ed8cbf5d183a6f27c8705b2d2da4563582b9b6c4876f3cdc6e41dd593e04bac5a3c4598cbe3f67d3bc723de2f13b4847b2266b7f2ae4b7f2f3c092e0fb5c78b6d65afd54141ec9ba29ec607ccd8c1329bce166029b8395805e6e18441c97";
            var clientPriv = "7a0fcb52b0497a6830a3efe0828054aa629fc9818bb1562c4a6b1af6";
            var clientPub = "3df2f085a43491c109567037d6d21f75fff6e1b458d81f63a29f673c67f1fc646fa07a938a678370e2c412e224d8ad8cb5d7d0d1bd2a340d07d107449d7c6498c3911cb275789fef3e27c3322cad2376b74bce8fd045831f2db8803131a6502b7a9b6e515e93c1653cc410a2fbea6be0d05b337fe3a992d4c871815adb3218d7bd10e2bf870006f45658c0e8e3f15e8e7bd67ccd104bf2445b2681a2739effa234dc567afeece9c4a1debdbb0c615539eeb756b7d4966ec8354d7add5812abfdfdd3fb82b284e00c3cbe11c195b85aef818c90f0220575e3eb629a52514b25425bd01cb390905874c241d3c9dc771a359694d7bc6bac42b3ababd78005a6360c";

            var secret = "8a5b80886761bcfe35c50bd16a5295d88071ad11d8201b0dcac83d1836c0603e1ced6a7e074e57cd2bc009a74723a88f2dda650110f2b5af8005f5d5b4805ca8169ee738c188be533c4fac444fc70dd280aad6cb818ecee408f7556dfb0b0af4f07b26d81dc2037a3fdf57f0d20373b0e63462e20ea5bb9481572dd1b2b5ef263dd88148e871e48e8146ceebc49d986dc79f42683ee0d64790f4cac79a85780169df50d2eb68a6fd76a9c19b20254701d09808c5a072845c467845b4928753396c1843407acacf2b6d8d9e1f6b07e9e272d553762e4cf8c16da2fb683b74c210722c4fe576a252353162f9a690de6b76f29db8b8f556942a57499ce310459351";

            var state = new TlsState(new MemoryStream());

            var exchange = new DHEKeyExchange(new NullKeyExchange());
            exchange.Init(state);

            state.Params[DHEKeyExchange.ParamP] = ToBI(p);
            state.Params[DHEKeyExchange.ParamG] = ToBI(g);
            state.Params[DHEKeyExchange.ParamX] = ToBI(serverPriv);

            var messages = exchange.GenerateHandshakeMessages();
            var message = messages.Single();

            Assert.IsInstanceOfType(message, typeof(SignedKeyExchangeMessage));

            var keyExchangeMessage = message as SignedKeyExchangeMessage;

            Assert.AreEqual(ToBI(p), keyExchangeMessage.P);
            Assert.AreEqual(ToBI(g), keyExchangeMessage.G);
            Assert.AreEqual(ToBI(serverPub), keyExchangeMessage.Y);

            var computedSecret = DHEKeyExchange.ComputeSharedSecret(ToBI(p), ToBI(serverPriv), ToBI(clientPub));

            Assert.AreEqual(ToBI(secret), computedSecret);
        }

        private static BigInteger ToBI(string p)
        {
            return BigIntegerExtensions.FromTlsBytes(HexConverter.FromHex(p));
        }
    }
}
