using System.Numerics;
using Lab3;
using NUnit.Framework;

namespace Lab3.Tests;

[TestFixture]
public class Gf2ServiceTests
{
    private readonly Gf2Service gf = new();

    [Test]
    public void AddUsesXor()
    {
        Assert.Multiple(() =>
        {
            Assert.That(gf.Add(0, 0), Is.Zero);
            Assert.That(gf.Add(0, 0x53), Is.EqualTo(0x53));
            Assert.That(gf.Add(0x57, 0x83), Is.EqualTo(0xD4));
            Assert.That(gf.Add(0x53, 0x53), Is.Zero);
        });
    }

    [Test]
    public void AESFieldKnownExamples()
    {
        Assert.Multiple(() =>
        {
            Assert.That(gf.Multiply(0x57, 0x83, 0x1B), Is.EqualTo(0xC1));
            Assert.That(gf.Inverse(0x53, 0x1B), Is.EqualTo(0xCA));
        });
    }

    [Test]
    public void ExactlyThirtyIrreduciblesEnumeratedFromSixtyFourCandidates()
    {
        var all = gf.GetIrreducibles();
        Assert.That(all, Has.Count.EqualTo(30));
        Assert.That(all, Is.Ordered.Ascending);
        Assert.That(all, Does.Contain((byte)0x1B));
        Assert.That(all, Does.Contain((byte)0x1D));
        Assert.That(all, Does.Not.Contain((byte)0x55));
        for (int x = 0; x < 256; x++)
            Assert.That(all.Contains((byte)x), Is.EqualTo(gf.IsIrreducible((byte)x)),
                $"Mismatch for polynomial 0x{0x100 | x:X3}");
    }

    [Test]
    public void InverseMultipliesToOneForEveryNonzeroByteAndEveryIrreducibleModulus()
    {
        foreach (byte modulus in gf.GetIrreducibles())
        for (int a = 1; a < 256; a++)
        {
            byte inverse = gf.Inverse((byte)a, modulus);
            Assert.That(gf.Multiply((byte)a, inverse, modulus), Is.EqualTo(1),
                $"a=0x{a:X2}, mod=0x{0x100 | modulus:X3}");
        }
    }

    [Test]
    public void InvalidModulusAndZeroInverseProduceExceptions()
    {
        Assert.Throws<ArgumentException>(() => gf.Multiply(2, 3, 0x00));
        Assert.Throws<ArgumentException>(() => gf.Inverse(3, 0x00));
        Assert.Throws<DivideByZeroException>(() => gf.Inverse(0, 0x1B));
    }

    [Test]
    public void FactorizationExtractsXAndOddFactorsWithMultiplicities()
    {
        Assert.That(gf.Factorize(BigInteger.One), Is.Empty);
        Assert.That(gf.Factorize(new BigInteger(0b101)),
            Is.EqualTo(new Dictionary<BigInteger, int> { [3] = 2 })); // x² + 1 = (x+1)²
        Assert.That(gf.Factorize(new BigInteger(0b1000101)),
            Is.EqualTo(new Dictionary<BigInteger, int> { [0b1011] = 2 })); // (x³+x+1)²
        Assert.That(gf.Factorize(new BigInteger(0b1000)),
            Is.EqualTo(new Dictionary<BigInteger, int> { [2] = 3 })); // x³
        Assert.That(gf.Factorize(new BigInteger(0b101000)),
            Is.EqualTo(new Dictionary<BigInteger, int> { [2] = 3, [3] = 2 })); // x³(x+1)²
        Assert.That(gf.Factorize(new BigInteger(0b1001)),
            Is.EqualTo(new Dictionary<BigInteger, int> { [3] = 1, [7] = 1 })); // (x+1)(x²+x+1)
        Assert.That(gf.Factorize(new BigInteger(0x11B)),
            Is.EqualTo(new Dictionary<BigInteger, int> { [0x11B] = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => gf.Factorize(BigInteger.Zero));
    }
}
