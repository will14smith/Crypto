using System.Collections.Generic;
using Crypto.Encryption;
using Crypto.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.Tests.Encryption
{
    [TestClass]
    public class AESCipherTests
    {
        [TestMethod]
        public void TestAES128()
        {
            var tests = new[]
            {
                new [] { "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97" },
                new [] { "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf" },
                new [] { "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688" },
                new [] { "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4" },
            };

            var aes = new AESCipher(128) { Key = HexConverter.FromHex("2b7e151628aed2a6abf7158809cf4f3c") };

            RunAESTests(tests, aes);
        }
        [TestMethod]
        public void TestAES192()
        {
            var tests = new[]
            {
                new [] { "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc" },
                new [] { "ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef" },
                new [] { "30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e" },
                new [] { "f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e" },
            };

            var aes = new AESCipher(192) { Key = HexConverter.FromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b") };

            RunAESTests(tests, aes);
        }
        [TestMethod]
        public void TestAES256()
        {
            var tests = new[]
            {
                new [] { "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8" },
                new [] { "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870" },
                new [] { "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d" },
                new [] { "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7" },
            };

            var aes = new AESCipher(256) { Key = HexConverter.FromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4") };

            RunAESTests(tests, aes);
        }

        private static void RunAESTests(IEnumerable<string[]> tests, IBlockCipher aes)
        {
            foreach (var test in tests)
            {
                var plain = test[0];
                var cipher = test[1];

                // encryption
                var plainInput = HexConverter.FromHex(plain);
                var actual = new byte[aes.BlockSize];

                aes.EncryptBlock(plainInput, 0, actual, 0);

                Assert.AreEqual(cipher, HexConverter.ToHex(actual));

                // decryption
                var cipherInput = HexConverter.FromHex(cipher);
                actual = new byte[aes.BlockSize];
                aes.DecryptBlock(cipherInput, 0, actual, 0);

                Assert.AreEqual(plain, HexConverter.ToHex(actual));
            }
        }

        [TestMethod]
        public void TestShiftRows()
        {
            var input = HexConverter.FromHex("0102030405060708090a0b0c0d0e0f10");
            var expected = "01060b10050a0f04090e03080d02070c";

            var state = AESCipher.ToState(input, 0);
            AESCipher.ShiftRows(state);
            var output = new byte[16];
            AESCipher.FromState(state, output, 0);

            Assert.AreEqual(expected, HexConverter.ToHex(output));
        }

        [TestMethod]
        public void TestMixColumns()
        {
            var input = HexConverter.FromHex("dbf201c6130a01c6532201c6455c01c6");
            var expected = "67e17a12ffc24aa907d22241a9384a05";

            var state = AESCipher.ToState(input, 0);
            AESCipher.MixColumns(state);
            var output = new byte[16];
            AESCipher.FromState(state, output, 0);

            Assert.AreEqual(expected, HexConverter.ToHex(output));
        }
        [TestMethod]
        public void TestInvMixColumns()
        {
            var input = HexConverter.FromHex("67e17a12ffc24aa907d22241a9384a05");
            var expected = "dbf201c6130a01c6532201c6455c01c6";

            var state = AESCipher.ToState(input, 0);
            AESCipher.InvMixColumns(state);
            var output = new byte[16];
            AESCipher.FromState(state, output, 0);

            Assert.AreEqual(expected, HexConverter.ToHex(output));
        }

        [TestMethod]
        public void TestKeyExpansion128()
        {
            var tests = new[]
            {
                new[] { "00000000000000000000000000000000", "00000000000000000000000000000000626363636263636362636363626363639b9898c9f9fbfbaa9b9898c9f9fbfbaa90973450696ccffaf2f457330b0fac99ee06da7b876a1581759e42b27e91ee2b7f2e2b88f8443e098dda7cbbf34b9290ec614b851425758c99ff09376ab49ba7217517873550620bacaf6b3cc61bf09b0ef903333ba9613897060a04511dfa9fb1d4d8e28a7db9da1d7bb3de4c664941b4ef5bcb3e92e21123e951cf6f8f188e" },
                new[] { "ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffe8e9e9e917161616e8e9e9e917161616adaeae19bab8b80f525151e6454747f0090e2277b3b69a78e1e7cb9ea4a08c6ee16abd3e52dc2746b33becd8179b60b6e5baf3ceb766d488045d385013c658e671d07db3c6b6a93bc2eb916bd12dc98de90d208d2fbb89b6ed5018dd3c7dd15096337366b988fad054d8e20d68a5335d8bf03f233278c5f366a027fe0e0514a3d60a3588e472f07b82d2d7858cd7c326" },
                new[] { "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5" },
                new[] { "6920e299a5202a6d656e636869746f2a", "6920e299a5202a6d656e636869746f2afa8807605fa82d0d3ac64e6553b2214fcf75838d90ddae80aa1be0e5f9a9c1aa180d2f1488d0819422cb6171db62a0dbbaed96ad323d173910f67648cb94d693881b4ab2ba265d8baad02bc36144fd50b34f195d096944d6a3b96f15c2fd9245a7007778ae6933ae0dd05cbbcf2dcefeff8bccf251e2ff5c5c32a3e7931f6d1924b7182e7555e77229674495ba78298cae127cdadb479ba8f220df3d4858f6b1" },
            };

            foreach (var test in tests)
            {
                var input = HexConverter.FromHex(test[0]);
                var expected = test[1];

                var output = AESCipher.BuildRoundKeys(input);

                Assert.AreEqual(expected, HexConverter.ToHex(output));
            }
        }

        [TestMethod]
        public void TestKeyExpansion192()
        {
            var tests = new[]
            {
                new[] { "000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000006263636362636363626363636263636362636363626363639b9898c9f9fbfbaa9b9898c9f9fbfbaa9b9898c9f9fbfbaa90973450696ccffaf2f457330b0fac9990973450696ccffac81d19a9a171d65353858160588a2df9c81d19a9a171d6537bebf49bda9a22c8891fa3a8d1958e51198897f8b8f941abc26896f718f2b43f91ed1797407899c659f00e3ee1094f9583ecbc0f9b1e08300af31fa74a8b8661137b885ff272c7ca432ac886d834c0b6d2c7df11984c5970" },
                new[] { "ffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffe8e9e9e917161616e8e9e9e917161616e8e9e9e917161616adaeae19bab8b80f525151e6454747f0adaeae19bab8b80fc5c2d8ed7f7a60e22d2b3104686c76f4c5c2d8ed7f7a60e21712403f686820dd454311d92d2f672de8edbfc09797df228f8cd3b7e7e4f36aa2a7e2b38f88859e67653a5ef0f2e57c2655c33bc1b130516316d2e2ec9e577c8bfb6d227b09885e67919b1aa620ab4bc53679a929a82ed5a25343f7d95acba9598e482fffaee3643a989acd1330b418" },
                new[] { "000102030405060708090a0b0c0d0e0f1011121314151617", "000102030405060708090a0b0c0d0e0f10111213141516175846f2f95c43f4fe544afef55847f0fa4856e2e95c43f4fe40f949b31cbabd4d48f043b810b7b34258e151ab04a2a5557effb5416245080c2ab54bb43a02f8f662e3a95d66410c08f501857297448d7ebdf1c6ca87f33e3ce510976183519b6934157c9ea351f1e01ea0372a995309167c439e77ff12051edd7e0e887e2fff68608fc842f9dcc154859f5f237a8d5a3dc0c02952beefd63ade601e7827bcdf2ca223800fd8aeda32a4970a331a78dc09c418c271e3a41d5d" },
            };

            foreach (var test in tests)
            {
                var input = HexConverter.FromHex(test[0]);
                var expected = test[1];

                var output = AESCipher.BuildRoundKeys(input);

                Assert.AreEqual(expected, HexConverter.ToHex(output));
            }
        }

        [TestMethod]
        public void TestKeyExpansion256()
        {
            var tests = new[]
            {
                new[] { "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000062636363626363636263636362636363aafbfbfbaafbfbfbaafbfbfbaafbfbfb6f6c6ccf0d0f0fac6f6c6ccf0d0f0fac7d8d8d6ad77676917d8d8d6ad77676915354edc15e5be26d31378ea23c38810e968a81c141fcf7503c717a3aeb070cab9eaa8f28c0f16d45f1c6e3e7cdfe62e92b312bdf6acddc8f56bca6b5bdbbaa1e6406fd52a4f79017553173f098cf11196dbba90b0776758451cad331ec71792fe7b0e89c4347788b16760b7b8eb91a6274ed0ba1739b7e252251ad14ce20d43b10f80a1753bf729c45c979e7cb706385" },
                new[] { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe8e9e9e917161616e8e9e9e9171616160fb8b8b8f04747470fb8b8b8f04747474a4949655d5f5f73b5b6b69aa2a0a08c355858dcc51f1f9bcaa7a7233ae0e064afa80ae5f2f755964741e30ce5e14380eca0421129bf5d8ae318faa9d9f81acde60ab7d014fde24653bc014ab65d42caa2ec6e658b5333ef684bc946b1b3d38b9b6c8a188f91685edc2d69146a702bdea0bd9f782beeac9743a565d1f216b65afc22349173b35ccfaf9e35dbc5ee1e050695ed132d7b41846ede24559cc8920f546d424f27de1e8088402b5b4dae355e" },
                new[] { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa573c29fa176c498a97fce93a572c09c1651a8cd0244beda1a5da4c10640badeae87dff00ff11b68a68ed5fb03fc15676de1f1486fa54f9275f8eb5373b8518dc656827fc9a799176f294cec6cd5598b3de23a75524775e727bf9eb45407cf390bdc905fc27b0948ad5245a4c1871c2f45f5a66017b2d387300d4d33640a820a7ccff71cbeb4fe5413e6bbf0d261a7dff01afafee7a82979d7a5644ab3afe6402541fe719bf500258813bbd55a721c0a4e5a6699a9f24fe07e572baacdf8cdea24fc79ccbf0979e9371ac23c6d68de36" },
            };

            foreach (var test in tests)
            {
                var input = HexConverter.FromHex(test[0]);
                var expected = test[1];

                var output = AESCipher.BuildRoundKeys(input);

                Assert.AreEqual(expected, HexConverter.ToHex(output));
            }
        }
    }
}
