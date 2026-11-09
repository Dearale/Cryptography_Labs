using System.Collections.Generic;
using System.Numerics;

namespace Lab2;

public class WienerAttackResult
{
    public bool Success;

    public BigInteger? DecryptExp;

    public BigInteger? Phi;

    public IReadOnlyList<WienerConvergent> Convergents;

    public WienerAttackResult(bool success, BigInteger? decryptExp, BigInteger? phi, IReadOnlyList<WienerConvergent> convergents)
    {
        Success = success;
        DecryptExp = decryptExp;
        Phi = phi;
        Convergents = convergents;
    }
}
