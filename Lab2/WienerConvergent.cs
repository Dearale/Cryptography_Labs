using System.Numerics;

namespace Lab2;

public struct WienerConvergent
{
    public BigInteger Numerator;
    public BigInteger Denominator;

    public WienerConvergent(BigInteger numerator, BigInteger denominator)
    {
        Numerator = numerator;
        Denominator = denominator;
    }
}
