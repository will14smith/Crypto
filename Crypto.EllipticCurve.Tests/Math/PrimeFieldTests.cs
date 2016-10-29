using Crypto.EllipticCurve.Maths;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.EllipticCurve.Tests.Math
{
    [TestClass]
    public class PrimeFieldTests
    {
        [TestMethod]
        public void TestAddition()
        {
            var field = new PrimeField(23);

            Assert.AreEqual(field.Int(4), field.Add(field.Int(18), field.Int(9)));
        }
        [TestMethod]
        public void TestSubtraction()
        {
            var field = new PrimeField(23);

            Assert.AreEqual(field.Int(16), field.Sub(field.Int(7), field.Int(14)));
        }

        [TestMethod]
        public void TestMultiplication()
        {
            var field = new PrimeField(23);

            Assert.AreEqual(field.Int(5), field.Multiply(field.Int(4), field.Int(7)));
        }
        [TestMethod]
        public void TestNegation()
        {
            var field = new PrimeField(23);

            Assert.AreEqual(field.Int(18), field.Negate(field.Int(5)));
        }
        [TestMethod]
        public void TestAdditiveInverse()
        {
            var field = new PrimeField(23);

            Assert.AreEqual(field.Int(0), field.Add(field.Int(5), field.Int(-5)));
        }
        [TestMethod]
        public void TestMultiplicativeInverse()
        {
            var field = new PrimeField(23);

            Assert.AreEqual(field.Int(18), field.Divide(field.Int(1), field.Int(9)));
        }
    }
}
