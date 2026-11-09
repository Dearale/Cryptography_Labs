using System.Numerics;

namespace Lab2;

public class MillerRabinPrimalityTest : ProbabilisticPrimalityTest
{
    protected override double ErrorProbabilityPerIteration() => 0.25;

    protected override bool RunIteration(BigInteger value, BigInteger randomBase)
    {
        BigInteger d = value - 1;
        int s = 0;

        while (d % 2 == 0)
        {
            d /= 2;
            s++;
        }

        BigInteger x = NumberTheoryService.ModPow(randomBase, d, value);

        if (x == 1 || x == value - 1)
            return true;

        for (int r = 1; r < s; r++)
        {
            x = (x * x) % value;

            if (x == value - 1)
                return true;

            if (x == 1)
                return false;
        }

        return false;
    }
}
