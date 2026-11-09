using System.Numerics;
using NUnit.Framework;

namespace Lab2.Tests;

[TestFixture]
public class NumberTheoryServiceTests : TimedTests
{
    [TestCase(0, 0, 0)]
    [TestCase(0, 14, 14)]
    [TestCase(0, -14, 14)]
    [TestCase(14, 0, 14)]
    [TestCase(-14, 0, 14)]
    [TestCase(7, 14, 7)]
    [TestCase(-7, 14, 7)]
    [TestCase(7, -14, 7)]
    [TestCase(15, 15, 15)]
    [TestCase(17, 31, 1)]
    [TestCase(240, 46, 2)]
    [TestCase(46, 240, 2)]
    [TestCase(-240, 46, 2)]
    [TestCase(240, -46, 2)]
    [TestCase(-240, -46, 2)]
    [TestCase(-46, 240, 2)]
    public void ExtendedGcd_ReturnsNonnegativeGcdAndBezoutCoefficients(int a, int b, int expectedGcd)
    {
        BezoutResult result = NumberTheoryService.ExtendedGcd(a, b);

        Assert.That(result.Gcd, Is.EqualTo(new BigInteger(expectedGcd)));
        Assert.That(a * result.X + b * result.Y, Is.EqualTo(result.Gcd));
    }

    [Test]
    public void ExtendedGcd_ClassroomExample_ReturnsExpectedCoefficients()
    {
        BezoutResult result = NumberTheoryService.ExtendedGcd(7, 14);

        Assert.That(result.Gcd, Is.EqualTo(new BigInteger(7)));
        Assert.That(result.X, Is.EqualTo(BigInteger.One));
        Assert.That(result.Y, Is.EqualTo(BigInteger.Zero));
    }

    [Test]
    public void ExtendedGcd_LargeIntegers_PreservesBezoutIdentity()
    {
        BigInteger a = (BigInteger.One << 512) - 1;
        BigInteger b = (BigInteger.One << 384) - 1;
        BigInteger expectedGcd = (BigInteger.One << 128) - 1;

        BezoutResult result = NumberTheoryService.ExtendedGcd(a, b);

        Assert.That(result.Gcd, Is.EqualTo(expectedGcd));
        Assert.That(a * result.X + b * result.Y, Is.EqualTo(expectedGcd));
    }
}
