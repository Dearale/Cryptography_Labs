using System;
using System.Numerics;

namespace Lab2;

public class WienerVulnerableKeyGenerator
{
    private const int MinPrimeBitLength = 16;
    private int primeBitLength;
    private double minProbability;
    private IPrimalityTest primalityTest;
    private Random random;

    public WienerVulnerableKeyGenerator(Rsa.PrimalityTestType testType, double minProbability, int primeBitLength)
    {
        if (minProbability < 0.5 || minProbability >= 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(minProbability));
        }

        if (primeBitLength < MinPrimeBitLength)
        {
            throw new ArgumentOutOfRangeException(nameof(primeBitLength));
        }

        this.primeBitLength = primeBitLength;
        this.minProbability = minProbability;
        primalityTest = ProbabilisticPrimalityTest.Create(testType);
        random = new Random();
    }

    public Rsa.KeyPair GenerateKeyPair()
    {
        while (true)
        {
            BigInteger p = NumberTheoryService.GeneratePrime(random, primeBitLength, minProbability, primalityTest);
            BigInteger q;

            do
            {
                q = NumberTheoryService.GeneratePrime(random, primeBitLength, minProbability, primalityTest);
            }
            while (q == p);

            if (p > q)
            {
                (p, q) = (q, p);
            }

            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            BigInteger dangerousBound = NumberTheoryService.IntegerFourthRoot(n) / 3;

            BigInteger d = NumberTheoryService.GetRandomBigInteger(random, 3, dangerousBound - 1);

            BezoutResult bezout = NumberTheoryService.ExtendedGcd(d, phi);

            if (bezout.Gcd != 1)
                continue;

            BigInteger e = NumberTheoryService.NormalizeMod(bezout.X, phi);

            Rsa.PublicKey publicKey = new(n, e);
            Rsa.PrivateKey privateKey = new(n, d);
            Rsa.KeyPair pair = new(publicKey, privateKey, p, q, phi);

            return pair;
        }
    }
}
