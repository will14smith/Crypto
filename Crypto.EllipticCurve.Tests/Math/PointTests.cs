using Crypto.EllipticCurve.Maths;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.EllipticCurve.Tests.Math
{
    [TestClass]
    public class PointTests
    {
        [TestMethod]
        public void TestAddition_Basic()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));
            var b = new Point<RealValue>(intField.Int(3), intField.Int(4));

            var c = Point<RealValue>.Add(curve, a, b);

            Assert.AreEqual(intField.Int(-3), c.X);
            Assert.AreEqual(intField.Int(2), c.Y);
        }

        [TestMethod]
        public void TestAddition_Same()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Add(curve, a, a);

            Assert.AreEqual(intField.Int(-1), c.X);
            Assert.AreEqual(intField.Int(-4), c.Y);
        }

        [TestMethod, Ignore]
        public void TestMultiplication_Zero()
        {
            // TODO infinty?
        }

        [TestMethod]
        public void TestMultiplication_One()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Multiply(curve, intField.Int(1), a);

            Assert.AreEqual(intField.Int(1), c.X);
            Assert.AreEqual(intField.Int(2), c.Y);
        }

        [TestMethod]
        public void TestMultiplication_Double()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Multiply(curve, intField.Int(2), a);

            Assert.AreEqual(intField.Int(-1), c.X);
            Assert.AreEqual(intField.Int(-4), c.Y);
        }

        [TestMethod]
        public void TestMultiplication_Three()
        {
            var intField = new RealField();
            var curve = new Curve<RealValue>(intField, intField.Int(-7), intField.Int(10));

            var a = new Point<RealValue>(intField.Int(1), intField.Int(2));

            var c = Point<RealValue>.Multiply(curve, intField.Int(3), a);

            Assert.AreEqual(intField.Int(9), c.X);
            Assert.AreEqual(intField.Int(-26), c.Y);
        }
    }
}
