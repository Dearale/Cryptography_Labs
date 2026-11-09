using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Lab2
{
    public static class NumberTheoryService
    {
        public static int LegendreSymbol(BigInteger a, BigInteger p)
        {
            if (p <= 2 || IsEven(p))
                throw new ArgumentException("p должно быть нечётным простым числом.", nameof(p));

            a = NormalizeMod(a, p);

            if (a == 0)
                return 0;

            BigInteger res = ModPow(a, (p - 1) / 2, p);

            if (res == 1)
                return 1;

            if (res == p - 1)
                return -1;

            throw new ArgumentException("p, вероятно, не является простым числом.", nameof(p));
        }

        public static int JacobiSymbol(BigInteger a, BigInteger n)
        {
            if (n <= 0 || IsEven(n))
                throw new ArgumentException("n должно быть положительным нечётным числом.", nameof(n));

            a = NormalizeMod(a, n);
            int result = 1;

            while (a != 0)
            {
                while (IsEven(a))
                {
                    a /= 2;
                    BigInteger nMod8 = n % 8;

                    if (nMod8 == 3 || nMod8 == 5)
                        result = -result;
                }

                (a, n) = (n, a);

                if (a % 4 == 3 && n % 4 == 3)
                    result = -result;
                a %= n;
            }

            return n == 1 ? result : 0;
        }

        public static BigInteger GcdEuclid(BigInteger a, BigInteger b)
        {
            a = Abs(a);
            b = Abs(b);

            while (b != 0)
            {
                BigInteger remainder = a % b;
                a = b;
                b = remainder;
            }

            return a;
        }

        public static BezoutResult ExtendedGcd(BigInteger a, BigInteger b)
        {
            if (a == 0)
                return new BezoutResult(Abs(b), 0, b < 0 ? -1 : 1);

            BezoutResult next = ExtendedGcd(b % a, a);
            BigInteger x = next.Y - (b / a) * next.X;
            BigInteger y = next.X;

            return new BezoutResult(next.Gcd, x, y);
        }

        public static BigInteger GcdBinary(BigInteger a, BigInteger b)
        {
            a = Abs(a);
            b = Abs(b);

            if (a == 0)
                return b;

            if (b == 0)
                return a;

            int commonPowerOfTwo = 0;

            while (IsEven(a) && IsEven(b))
            {
                a /= 2;
                b /= 2;

                commonPowerOfTwo++;
            }

            while (IsEven(a))
                a /= 2;

            while (b != 0)
            {
                while (IsEven(b))
                    b /= 2;

                if (a > b)
                    (a, b) = (b, a);

                b -= a;
            }

            return a << commonPowerOfTwo;
        }

        public static BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
        {
            if (modulus <= 0)
                throw new ArgumentException("Модуль должен быть положительным.", nameof(modulus));

            if (exponent < 0)
                throw new ArgumentException("Показатель степени не должен быть отрицательным.", nameof(exponent));

            value = NormalizeMod(value, modulus);
            BigInteger result = 1 % modulus;

            while (exponent > 0)
            {
                if (!IsEven(exponent))
                {
                    result = (result * value) % modulus;
                }

                exponent /= 2;
                value = (value * value) % modulus;
            }

            return result;
        }

        public static BigInteger EulerPhiByDefinition(BigInteger n)
        {
            ValidatePositiveN(n);

            BigInteger result = 0;

            for (BigInteger k = 1; k <= n; k++)
            {
                if (GcdEuclid(k, n) == 1)
                    result++;
            }

            return result;
        }

        public static BigInteger EulerPhiByFactorization(BigInteger n)
        {
            ValidatePositiveN(n);

            Dictionary<BigInteger, int> factors = Factorize(n);
            BigInteger result = n;

            foreach (BigInteger prime in factors.Keys)
            {
                result = result / prime * (prime - 1);
            }

            return result;
        }

        public static BigInteger EulerPhiByDft(BigInteger n)
        {
            ValidatePositiveN(n);

            if (n > int.MaxValue)
            {
                throw new ArgumentException("Для вычисления через ДПФ n должно помещаться в int.", nameof(n));
            }

            int value = (int)n;
            double sum = 0.0;

            for (int k = 1; k <= value; k++)
            {
                BigInteger gcd = GcdEuclid(k, value);
                double angle = 2.0 * Math.PI * k / value;
                sum += (double)gcd * Math.Cos(angle);
            }

            double rounded = Math.Round(sum);

            return new BigInteger(rounded);
        }

        public static BigInteger Carmichael(BigInteger n)
        {
            ValidatePositiveN(n);

            Dictionary<BigInteger, int> factors = Factorize(n);

            BigInteger result = 1;

            foreach (KeyValuePair<BigInteger, int> factor in factors)
            {
                BigInteger prime = factor.Key;
                int exponent = factor.Value;

                BigInteger current;

                if (prime == 2 && exponent >= 3)
                {
                    current = IntegerPow(2, exponent - 2);
                }
                else
                {
                    current = IntegerPow(prime, exponent - 1) * (prime - 1);
                }

                result = Lcm(result, current);
            }

            return result;
        }

        private static Dictionary<BigInteger, int> Factorize(BigInteger n)
        {
            Dictionary<BigInteger, int> result = new();
            BigInteger value = n;

            int exponentOfTwo = 0;

            while (value % 2 == 0)
            {
                value /= 2;
                exponentOfTwo++;
            }

            if (exponentOfTwo > 0)
                result[2] = exponentOfTwo;

            for (BigInteger divisor = 3; divisor * divisor <= value; divisor += 2)
            {
                int exponent = 0;

                while (value % divisor == 0)
                {
                    value /= divisor;
                    exponent++;
                }

                if (exponent > 0)
                    result[divisor] = exponent;
            }

            if (value > 1)
                result[value] = 1;

            return result;
        }

        private static BigInteger Lcm(BigInteger a, BigInteger b)
        {
            if (a == 0 || b == 0)
                return 0;

            return Abs(a / GcdEuclid(a, b) * b);
        }

        private static BigInteger IntegerPow(BigInteger value, int exponent)
        {
            BigInteger result = 1;
            BigInteger current = value;
            int power = exponent;

            while (power > 0)
            {
                if (power % 2 != 0)
                    result *= current;
                power /= 2;

                if (power > 0)
                    current *= current;
            }

            return result;
        }

        public static BigInteger IntegerSqrt(BigInteger value)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);

            if (value < 2)
                return value;

            int bitLength = (int)value.GetBitLength();
            BigInteger x = BigInteger.One << ((bitLength + 1) / 2);

            while (true)
            {
                BigInteger next = (x + value / x) / 2;

                if (next >= x)
                    return x;

                x = next;
            }
        }

        public static BigInteger IntegerFourthRoot(BigInteger value)
        {
            return IntegerSqrt(IntegerSqrt(value));
        }

        public static BigInteger GenerateOddCandidate(Random random, int primeBitLength)
        {
            int byteLength = (primeBitLength + 7) / 8;
            byte[] bytes = new byte[byteLength];
            random.NextBytes(bytes);
            int excessBits = byteLength * 8 - primeBitLength;

            bytes[0] &= (byte)(0xFF >> excessBits);

            int highestBitPosition = 7 - excessBits;
            bytes[0] |= (byte)(1 << highestBitPosition);

            bytes[^1] |= 1;

            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        public static BigInteger GeneratePrime(Random random, int primeBitLength, double minProbability, IPrimalityTest primalityTest)
        {
            while (true)
            {
                BigInteger candidate = GenerateOddCandidate(random, primeBitLength);

                if (primalityTest.IsProbablyPrime(candidate, minProbability))
                {
                    return candidate;
                }
            }
        }

        public static BigInteger GetRandomBigInteger(Random random, int length)
        {
            var bytes = new byte[length];
            random.NextBytes(bytes);
            return new BigInteger(bytes, isUnsigned: true);
        }

        public static BigInteger GetRandomBigInteger(Random random, BigInteger min, BigInteger max)
        {
            if (min > max)
            {
                throw new ArgumentException("min > max");
            }

            BigInteger range = max - min + 1;

            if (range == 1)
                return min;

            int bitLength = (int)(range - 1).GetBitLength();
            int byteLength = (bitLength + 7) / 8;
            int excessBits = byteLength * 8 - bitLength;
            byte[] bytes = new byte[byteLength];

            while (true)
            {
                random.NextBytes(bytes);

                bytes[0] &= (byte)(0xFF >> excessBits);

                BigInteger value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);

                if (value < range)
                    return min + value;
            }
        }

        public static BigInteger NormalizeMod(BigInteger value, BigInteger modulus)
        {
            BigInteger result = value % modulus;

            if (result < 0)
                result += modulus;

            return result;
        }

        private static bool IsEven(BigInteger value)
        {
            return value % 2 == 0;
        }

        public static BigInteger Abs(BigInteger value)
        {
            return value < 0 ? -value : value;
        }

        private static void ValidatePositiveN(BigInteger n)
        {
            if (n <= 0)
                throw new ArgumentException("n должно быть положительным.", nameof(n));
        }
    }
}
