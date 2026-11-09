using System;
using System.Numerics;

namespace Lab2;

public abstract class ProbabilisticPrimalityTest : IPrimalityTest
{
    private Random random;

    protected ProbabilisticPrimalityTest()
    {
        random = new Random();
    }

    protected abstract double ErrorProbabilityPerIteration();

    public bool IsProbablyPrime(BigInteger value, double minProbability)
    {
        if (minProbability < 0.5 || minProbability >= 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(minProbability));
        }

        if (value < 2)
            return false;

        if (value == 2 || value == 3)
            return true;

        if (value % 2 == 0)
            return false;

        int iterations = (int)Math.Ceiling(Math.Log(1.0 - minProbability, ErrorProbabilityPerIteration()));

        for (int i = 0; i < iterations; i++)
        {
            BigInteger randomBase = NumberTheoryService.GetRandomBigInteger(random, value.GetByteCount()) % (value - 1) + 1;

            if (!RunIteration(value, randomBase))
                return false;
        }

        return true;
    }

    public static IPrimalityTest Create(Rsa.PrimalityTestType testType)
    {
        return testType switch
        {
            Rsa.PrimalityTestType.Fermat => new FermatPrimalityTest(),
            Rsa.PrimalityTestType.SolovayStrassen => new SolovayStrassenPrimalityTest(),
            Rsa.PrimalityTestType.MillerRabin => new MillerRabinPrimalityTest(),
            _ => throw new ArgumentOutOfRangeException(nameof(testType))
        };
    }

    protected abstract bool RunIteration(BigInteger value, BigInteger randomBase);
}
