using System.Numerics;
using NUnit.Framework;

namespace Lab2.Tests;

[TestFixture]
public class WienerAttackServiceTests : TimedTests
{
    [Test]
    public void Attack_KnownVulnerableKey_RecoversExponentAndPhi()
    {
        var result = new WienerAttackService().Attack(new Rsa.PublicKey(90581, 17993));
        Assert.That(result.Success, Is.True);
        Assert.That(result.DecryptExp, Is.EqualTo(new BigInteger(5)));
        Assert.That(result.Phi, Is.EqualTo(new BigInteger(89964)));
        Assert.That(result.Convergents.Any(value => value.Numerator == 1 && value.Denominator == 5), Is.True);
        Assert.That(result.Convergents.All(value => value.Denominator > 0), Is.True);
    }

    [Test]
    public void Attack_KeyWithoutSmallExponent_ReportsFailure()
    {
        var result = new WienerAttackService().Attack(new Rsa.PublicKey(3233, 17));
        Assert.That(result.Success, Is.False);
        Assert.That(result.DecryptExp, Is.Null);
        Assert.That(result.Phi, Is.Null);
        Assert.That(result.Convergents, Is.Not.Empty);
    }

    [Test]
    public void GeneratedVulnerableKey_CanBeAttackedAndDecrypted()
    {
        var generator = new WienerVulnerableKeyGenerator(Rsa.PrimalityTestType.MillerRabin, 0.999999999999, 16);
        Rsa.KeyPair pair = generator.GenerateKeyPair();
        var result = new WienerAttackService().Attack(pair.PublicKey);
        Assert.That(pair.P < pair.Q && pair.Q < 2 * pair.P, Is.True);
        Assert.That(81 * BigInteger.Pow(pair.PrivateKey.D, 4) < pair.PublicKey.N, Is.True);
        Assert.That(result.Success, Is.True);
        Assert.That(result.DecryptExp, Is.EqualTo(pair.PrivateKey.D));
        Assert.That(result.Phi, Is.EqualTo(pair.Phi));
        BigInteger ciphertext = NumberTheoryService.ModPow(12345, pair.PublicKey.E, pair.PublicKey.N);
        Assert.That(NumberTheoryService.ModPow(ciphertext, result.DecryptExp!.Value, pair.PublicKey.N), Is.EqualTo(new BigInteger(12345)));
    }

    [TestCase(0, 17)]
    [TestCase(1, 17)]
    [TestCase(3233, 0)]
    public void Attack_RejectsInvalidPublicKey(int n, int e)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new WienerAttackService().Attack(new Rsa.PublicKey(n, e)));
    }
}
