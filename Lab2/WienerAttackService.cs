using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lab2;

public class WienerAttackService
{
    public WienerAttackResult Attack(Rsa.PublicKey publicKey)
    {
        BigInteger n = publicKey.N;
        BigInteger e = publicKey.E;

        if (n <= 1)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey), "Модуль должен быть больше 1.");
        }

        if (e <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey), "Открытая экспонента должна быть положительной.");
        }

        List<WienerConvergent> convergents = new List<WienerConvergent>();

        BigInteger currentNumerator = e;
        BigInteger currentDenominator = n;

        BigInteger hMinus2 = 0;
        BigInteger hMinus1 = 1;
        BigInteger kMinus2 = 1;
        BigInteger kMinus1 = 0;

        while (currentDenominator != 0)
        {
            BigInteger coef = currentNumerator / currentDenominator;

            BigInteger h = coef * hMinus1 + hMinus2;
            BigInteger k = coef * kMinus1 + kMinus2;
            WienerConvergent convergent = new(h, k);
            convergents.Add(convergent);

            BigInteger candidateK = h;
            BigInteger candidateD = k;

            if (candidateK != 0)
            {
                BigInteger value = e * candidateD - 1;

                if (value % candidateK == 0)
                {
                    BigInteger candidatePhi = value / candidateK;

                    if (TryRecoverFactors(n, candidatePhi, out BigInteger p, out BigInteger q))
                    {
                        return new WienerAttackResult(true, candidateD, candidatePhi, convergents);
                    }
                }
            }

            BigInteger remainder = currentNumerator % currentDenominator;
            currentNumerator = currentDenominator;
            currentDenominator = remainder;

            hMinus2 = hMinus1;
            hMinus1 = h;
            kMinus2 = kMinus1;
            kMinus1 = k;
        }

        return new WienerAttackResult(false, null, null, convergents);
    }

    private static bool TryRecoverFactors(BigInteger n, BigInteger phi, out BigInteger p, out BigInteger q)
    {
        p = 0;
        q = 0;

        if (phi <= 0 || phi >= n)
            return false;

        BigInteger sum = n - phi + 1;

        BigInteger discriminant = sum * sum - 4 * n;

        if (discriminant < 0)
            return false;

        BigInteger sqrtDiscriminant = NumberTheoryService.IntegerSqrt(discriminant);

        if (sqrtDiscriminant * sqrtDiscriminant != discriminant)
        {
            return false;
        }

        p = (sum + sqrtDiscriminant) / 2;
        q = (sum - sqrtDiscriminant) / 2;

        return p > 1 && q > 1;
    }
}
