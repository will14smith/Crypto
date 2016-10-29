using Crypto.EllipticCurve.Maths;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.EllipticCurve.Tests.Math
{
    [TestClass]
    public class PrimeCurveTests
    {
        [TestMethod]
        public void TestAddition_Basic()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeFieldValue>(field.Int(3), field.Int(6));
            var b = new Point<PrimeFieldValue>(field.Int(11), field.Int(17));

            var c = Point<PrimeFieldValue>.Add(curve, a, b);

            Assert.AreEqual(field.Int(47), c.X);
            Assert.AreEqual(field.Int(79), c.Y);
        }

        [TestMethod]
        public void TestAddition_Same()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeFieldValue>(field.Int(59), field.Int(32));

            var c = Point<PrimeFieldValue>.Add(curve, a, a);

            Assert.AreEqual(field.Int(80), c.X);
            Assert.AreEqual(field.Int(10), c.Y);
        }

        [TestMethod, Ignore]
        public void TestMultiplication_Zero()
        {
            // TODO infinty?
        }

        [TestMethod]
        public void TestMultiplication_One()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeFieldValue>(field.Int(3), field.Int(6));

            var c = Point<PrimeFieldValue>.Multiply(curve, 1, a);

            Assert.AreEqual(field.Int(3), c.X);
            Assert.AreEqual(field.Int(6), c.Y);
        }

        [TestMethod]
        public void TestMultiplication_Double()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeFieldValue>(field.Int(3), field.Int(6));

            var c = Point<PrimeFieldValue>.Multiply(curve, 2, a);

            Assert.AreEqual(field.Int(80), c.X);
            Assert.AreEqual(field.Int(10), c.Y);
        }

        [TestMethod]
        public void TestMultiplication_Three()
        {
            var field = new PrimeField(97);
            var curve = new Curve<PrimeFieldValue>(field, field.Int(2), field.Int(3));

            var a = new Point<PrimeFieldValue>(field.Int(3), field.Int(6));

            var c = Point<PrimeFieldValue>.Multiply(curve, 3, a);

            Assert.AreEqual(field.Int(80), c.X);
            Assert.AreEqual(field.Int(87), c.Y);
        }
    }
}
