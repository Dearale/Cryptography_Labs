using System.Numerics;
using NUnit.Framework;

namespace Lab2.Tests;

[TestFixture]
public class RsaTests : TimedTests
{
    private Rsa rsa = null!;

    [SetUp]
    public void CreateRsa()
    {
        rsa = new Rsa(Rsa.PrimalityTestType.MillerRabin, 0.999999999999, 16);
    }

    [Test]
    public void PrivateKey_StoresProvidedExponent()
    {
        var key = new Rsa.PrivateKey(3233, 2753);
        Assert.That(key.N, Is.EqualTo(new BigInteger(3233)));
        Assert.That(key.D, Is.EqualTo(new BigInteger(2753)));
    }

    [Test]
    public void GeneratedKeys_SatisfyRsaRelationsAndGenerationConstraints()
    {
        Rsa.KeyPair pair = rsa.CurrentKeyPair;
        Assert.That(pair.P.GetBitLength(), Is.EqualTo(16L));
        Assert.That(pair.Q.GetBitLength(), Is.EqualTo(16L));
        Assert.That(pair.PublicKey.N, Is.EqualTo(pair.P * pair.Q));
        Assert.That(pair.PrivateKey.N, Is.EqualTo(pair.PublicKey.N));
        Assert.That(pair.Phi, Is.EqualTo((pair.P - 1) * (pair.Q - 1)));
        Assert.That(pair.PublicKey.E * pair.PrivateKey.D % pair.Phi, Is.EqualTo(BigInteger.One));
        Assert.That(BigInteger.Abs(pair.P - pair.Q) >= (BigInteger.One << 14), Is.True);
        Assert.That(pair.PrivateKey.D > NumberTheoryService.IntegerFourthRoot(pair.PublicKey.N) / 3, Is.True);
    }

    [Test]
    public void EncryptDecrypt_RestoresNumbersIncludingRangeBoundaries()
    {
        foreach (BigInteger message in new[] { BigInteger.Zero, BigInteger.One, new BigInteger(42), rsa.CurrentKeyPair.PublicKey.N - 1 })
            Assert.That(rsa.Decrypt(rsa.Encrypt(message)), Is.EqualTo(message));
    }

    [Test]
    public void EncryptDecrypt_RestoresBinaryDataWithZeroAndHighBytes()
    {
        byte[] bytes = { 0, 0, 0, 0, 1, 128, 255, 0, 0, 42, 0, 0 };
        Assert.That(rsa.Decrypt(rsa.Encrypt(bytes)), Is.EqualTo(bytes));
    }

    [TestCase("")]
    [TestCase("Привет, RSA! 🔐")]
    public void EncryptDecrypt_RestoresUtf8Text(string text)
    {
        Assert.That(rsa.DecryptString(rsa.EncryptString(text)), Is.EqualTo(text));
    }

    [Test]
    public void EncryptDecrypt_RestoresEmptyByteArray()
    {
        Assert.That(rsa.Decrypt(rsa.Encrypt(Array.Empty<byte>())), Is.Empty);
    }

    [Test]
    public void GenerateNewKeyPair_UpdatesCurrentKeysAndPreservesRoundTrip()
    {
        Rsa.KeyPair pair = rsa.GenerateNewKeyPair();
        Assert.That(rsa.CurrentKeyPair.PublicKey.N, Is.EqualTo(pair.PublicKey.N));
        Assert.That(rsa.CurrentKeyPair.PrivateKey.D, Is.EqualTo(pair.PrivateKey.D));
        Assert.That(pair.PublicKey.E * pair.PrivateKey.D % pair.Phi, Is.EqualTo(BigInteger.One));
        Assert.That(rsa.Decrypt(rsa.Encrypt(new BigInteger(12345))), Is.EqualTo(new BigInteger(12345)));
    }

    [Test]
    public void EncryptDecrypt_RejectsValuesOutsideModulus()
    {
        BigInteger n = rsa.CurrentKeyPair.PublicKey.N;
        Assert.Throws<ArgumentOutOfRangeException>(() => rsa.Encrypt(new BigInteger(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => rsa.Encrypt(n));
        Assert.Throws<ArgumentOutOfRangeException>(() => rsa.Decrypt(new BigInteger(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => rsa.Decrypt(n));
    }
}
