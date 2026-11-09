using System.Numerics;

namespace Lab2;

public class FermatPrimalityTest : ProbabilisticPrimalityTest
{
    protected override double ErrorProbabilityPerIteration() => 0.5;

    protected override bool RunIteration(BigInteger value, BigInteger randomBase)
    {
        BigInteger result = NumberTheoryService.ModPow(randomBase, value - 1, value);

        return result == 1;
    }
}
