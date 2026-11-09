using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Lab2
{
    public struct BezoutResult
    {
        public BigInteger Gcd;
        public BigInteger X;
        public BigInteger Y;

        public BezoutResult(BigInteger gcd, BigInteger x, BigInteger y)
        {
            Gcd = gcd;
            X = x;
            Y = y;
        }
    }
}
