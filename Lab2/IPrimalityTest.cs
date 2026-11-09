using System.Numerics;

namespace Lab2;

public interface IPrimalityTest
{
    bool IsProbablyPrime(BigInteger value, double minimumProbability);
}
