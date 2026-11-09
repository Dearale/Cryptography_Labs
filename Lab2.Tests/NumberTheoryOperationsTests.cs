using System.Numerics;
using NUnit.Framework;

namespace Lab2.Tests;

[TestFixture]
public class NumberTheoryOperationsTests : TimedTests
{
    [TestCase(0, 7, 0)]
    [TestCase(1, 7, 1)]
    [TestCase(2, 7, 1)]
    [TestCase(3, 7, -1)]
    [TestCase(-1, 7, -1)]
    [TestCase(-1, 13, 1)]
    public void LegendreSymbol_ReturnsExpectedValue(int a, int p, int expected)
    {
        Assert.That(NumberTheoryService.LegendreSymbol(a, p), Is.EqualTo(expected));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(4)]
    [TestCase(-7)]
    public void LegendreSymbol_RejectsInvalidDenominator(int p)
    {
        Assert.Throws<ArgumentException>(() => NumberTheoryService.LegendreSymbol(1, p));
    }

    [TestCase(1001, 9907, -1)]
    [TestCase(2, 15, 1)]
    [TestCase(6, 15, 0)]
    [TestCase(-1, 7, -1)]
    [TestCase(0, 1, 1)]
    [TestCase(0, 9, 0)]
    public void JacobiSymbol_ReturnsExpectedValue(int a, int n, int expected)
    {
        Assert.That(NumberTheoryService.JacobiSymbol(a, n), Is.EqualTo(expected));
    }

    [TestCase(0)]
    [TestCase(-3)]
    [TestCase(2)]
    [TestCase(10)]
    public void JacobiSymbol_RejectsInvalidDenominator(int n)
    {
        Assert.Throws<ArgumentException>(() => NumberTheoryService.JacobiSymbol(1, n));
    }

    [TestCase(0, 0)]
    [TestCase(0, -15)]
    [TestCase(-15, 0)]
    [TestCase(252, 105)]
    [TestCase(-240, 46)]
    [TestCase(-240, -46)]
    [TestCase(17, 31)]
    public void GcdAlgorithms_AgreeWithExpectedGcd(int a, int b)
    {
        BigInteger expected = BigInteger.GreatestCommonDivisor(a, b);
        Assert.That(NumberTheoryService.GcdEuclid(a, b), Is.EqualTo(expected));
        Assert.That(NumberTheoryService.GcdBinary(a, b), Is.EqualTo(expected));
    }

    [TestCase(7, 128, 13, 3)]
    [TestCase(-3, 3, 11, 6)]
    [TestCase(2, 10, 1000, 24)]
    [TestCase(0, 0, 7, 1)]
    [TestCase(0, 0, 1, 0)]
    [TestCase(3, 0, 7, 1)]
    public void ModPow_ReturnsNormalizedPower(int value, int exponent, int modulus, int expected)
    {
        Assert.That(NumberTheoryService.ModPow(value, exponent, modulus), Is.EqualTo(new BigInteger(expected)));
    }

    [TestCase(1, 1)]
    [TestCase(2, 1)]
    [TestCase(9, 6)]
    [TestCase(36, 12)]
    [TestCase(97, 96)]
    [TestCase(360, 96)]
    public void EulerPhi_ThreeMethodsAgree(int n, int expected)
    {
        BigInteger phi = expected;
        Assert.That(NumberTheoryService.EulerPhiByDefinition(n), Is.EqualTo(phi));
        Assert.That(NumberTheoryService.EulerPhiByFactorization(n), Is.EqualTo(phi));
        Assert.That(NumberTheoryService.EulerPhiByDft(n), Is.EqualTo(phi));
    }

    [TestCase(1, 1)]
    [TestCase(2, 1)]
    [TestCase(4, 2)]
    [TestCase(8, 2)]
    [TestCase(16, 4)]
    [TestCase(9, 6)]
    [TestCase(15, 4)]
    [TestCase(36, 6)]
    [TestCase(561, 80)]
    public void Carmichael_ReturnsExpectedValue(int n, int expected)
    {
        Assert.That(NumberTheoryService.Carmichael(n), Is.EqualTo(new BigInteger(expected)));
    }

    [TestCase(-17, 40, 23)]
    [TestCase(17, 40, 17)]
    [TestCase(80, 40, 0)]
    public void NormalizeMod_ReturnsNonnegativeRemainder(int value, int modulus, int expected)
    {
        Assert.That(NumberTheoryService.NormalizeMod(value, modulus), Is.EqualTo(new BigInteger(expected)));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(15)]
    [TestCase(16)]
    [TestCase(17)]
    [TestCase(65535)]
    public void IntegerSqrt_ReturnsFloorOfRoot(int n)
    {
        BigInteger root = NumberTheoryService.IntegerSqrt(n);
        Assert.That(root * root <= n && (root + 1) * (root + 1) > n, Is.True);
    }

    [Test]
    public void IntegerSqrt_HandlesLargePerfectSquareAndNeighbors()
    {
        BigInteger expected = (BigInteger.One << 256) + 123;
        BigInteger square = expected * expected;
        Assert.That(NumberTheoryService.IntegerSqrt(square - 1), Is.EqualTo(expected - 1));
        Assert.That(NumberTheoryService.IntegerSqrt(square), Is.EqualTo(expected));
        Assert.That(NumberTheoryService.IntegerSqrt(square + 1), Is.EqualTo(expected));
    }

    [TestCase(0, 0)]
    [TestCase(1, 1)]
    [TestCase(15, 1)]
    [TestCase(16, 2)]
    [TestCase(17, 2)]
    [TestCase(80, 2)]
    [TestCase(81, 3)]
    [TestCase(82, 3)]
    public void IntegerFourthRoot_ReturnsFloorOfRoot(int n, int expected)
    {
        Assert.That(NumberTheoryService.IntegerFourthRoot(n), Is.EqualTo(new BigInteger(expected)));
    }

    [TestCase(16)]
    [TestCase(19)]
    [TestCase(32)]
    [TestCase(128)]
    public void GenerateOddCandidate_PreservesRequestedBitLength(int bitLength)
    {
        var random = new Random(42);
        for (int i = 0; i < 32; i++)
        {
            BigInteger candidate = NumberTheoryService.GenerateOddCandidate(random, bitLength);
            Assert.That(candidate.GetBitLength(), Is.EqualTo((long)bitLength));
            Assert.That(candidate.IsEven, Is.False);
        }
    }

    [TestCase(3, 3)]
    [TestCase(-9, -2)]
    [TestCase(-2, 5)]
    [TestCase(128, 256)]
    [TestCase(0, 255)]
    public void GetRandomBigInteger_StaysWithinInclusiveRange(int min, int max)
    {
        var random = new Random(42);
        for (int i = 0; i < 64; i++)
        {
            BigInteger value = NumberTheoryService.GetRandomBigInteger(random, min, max);
            Assert.That(value >= min && value <= max, Is.True);
        }
    }
}
