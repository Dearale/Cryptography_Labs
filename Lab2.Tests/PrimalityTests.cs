using System.Numerics;
using NUnit.Framework;

namespace Lab2.Tests;

[TestFixture]
public class PrimalityTests : TimedTests
{
    [TestCase(Rsa.PrimalityTestType.Fermat)]
    [TestCase(Rsa.PrimalityTestType.SolovayStrassen)]
    [TestCase(Rsa.PrimalityTestType.MillerRabin)]
    public void PublicTest_AcceptsPrimesAndRejectsTrivialNonPrimes(Rsa.PrimalityTestType type)
    {
        IPrimalityTest test = ProbabilisticPrimalityTest.Create(type);
        foreach (int prime in new[] { 2, 3, 5, 17, 97, 104729 })
            Assert.That(test.IsProbablyPrime(prime, 0.99), Is.True, $"n={prime}");
        foreach (int number in new[] { -7, 0, 1, 4, 16, 100 })
            Assert.That(test.IsProbablyPrime(number, 0.99), Is.False, $"n={number}");
    }

    [TestCase(0.49)]
    [TestCase(1.0)]
    [TestCase(-1.0)]
    public void PublicTest_RejectsInvalidProbability(double probability)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new MillerRabinPrimalityTest().IsProbablyPrime(17, probability));
    }

    [TestCase(17, 3, true)]
    [TestCase(9, 2, false)]
    [TestCase(15, 3, false)]
    [TestCase(561, 2, true)]
    public void FermatIteration_HandlesPrimesCompositesAndCarmichaelNumber(int n, int a, bool expected)
    {
        Assert.That(new FermatProbe().Check(n, a), Is.EqualTo(expected));
    }

    [TestCase(17, 3, true)]
    [TestCase(9, 2, false)]
    [TestCase(9, 3, false)]
    [TestCase(21, 2, false)]
    public void SolovayStrassenIteration_RejectsWitnessesAndCommonFactors(int n, int a, bool expected)
    {
        Assert.That(new SolovayStrassenProbe().Check(n, a), Is.EqualTo(expected));
    }

    [TestCase(13, 2, true)]
    [TestCase(17, 3, true)]
    [TestCase(9, 2, false)]
    [TestCase(21, 8, false)]
    [TestCase(341, 2, false)]
    [TestCase(2047, 2, true)]
    public void MillerRabinIteration_HandlesWitnessesAndStrongPseudoprime(int n, int a, bool expected)
    {
        Assert.That(new MillerRabinProbe().Check(n, a), Is.EqualTo(expected));
    }

    [Test]
    public void Factory_RejectsUnknownTestType()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ProbabilisticPrimalityTest.Create((Rsa.PrimalityTestType)99));
    }

    private class FermatProbe : FermatPrimalityTest
    {
        public bool Check(BigInteger n, BigInteger a) => RunIteration(n, a);
    }

    private class SolovayStrassenProbe : SolovayStrassenPrimalityTest
    {
        public bool Check(BigInteger n, BigInteger a) => RunIteration(n, a);
    }

    private class MillerRabinProbe : MillerRabinPrimalityTest
    {
        public bool Check(BigInteger n, BigInteger a) => RunIteration(n, a);
    }
}
