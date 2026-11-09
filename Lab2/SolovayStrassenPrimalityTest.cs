using System.Numerics;

namespace Lab2;

public class SolovayStrassenPrimalityTest : ProbabilisticPrimalityTest
{
    protected override double ErrorProbabilityPerIteration() => 0.5;

    protected override bool RunIteration(BigInteger value, BigInteger randomBase)
    {
        int jacobi = NumberTheoryService.JacobiSymbol(randomBase, value);

        if (jacobi == 0)
            return false;

        BigInteger left = NumberTheoryService.ModPow(randomBase, (value - 1) / 2, value);

        BigInteger right = jacobi == -1 ? value - 1 : jacobi;

        return left == right;
    }
}
