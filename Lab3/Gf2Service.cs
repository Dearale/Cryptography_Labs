using System.Numerics;

namespace Lab3;

public class Gf2Service
{
    public byte Add(byte a, byte b) => (byte)(a ^ b);

    public byte Multiply(byte a, byte b, byte mod)
    {
        ValidateMod(mod);
        return MultiplyUnchecked(a, b, mod);
    }

    public byte Inverse(byte a, byte mod)
    {
        ValidateMod(mod);
        if (a == 0)
            throw new DivideByZeroException("У нуля нет обратного");

        int exp = 254;
        byte res = 1;
        byte factor = a;
        while (exp > 0)
        {
            if ((exp & 1) != 0)
                res = MultiplyUnchecked(res, factor, mod);
            factor = MultiplyUnchecked(factor, factor, mod);
            exp >>= 1;
        }
        return res;
    }

    public bool IsIrreducible(byte mod)
    {

        if ((mod & 1) == 0)
            return false;

        int fullMod = 0x100 | mod;

        if ((int.PopCount(fullMod) & 1) == 0)
            return false;

        for (int div = 5; div < 32; div += 2)
            if (Remainder(fullMod, div) == 0)
                return false;
        return true;
    }

    public List<byte> GetIrreducibles()
    {
        List<byte> res = new(30);
        for (int mid = 0; mid < 64; mid++)
        {
            int seventh = (int.PopCount(mid) & 1) == 0 ? 1 : 0;
            byte mod = (byte)((seventh << 7) | (mid << 1) | 1);
            if (IsIrreducible(mod))
                res.Add(mod);
        }
        res.Sort();
        return res;
    }

    public Dictionary<BigInteger, int> Factorize(BigInteger polynom)
    {
        if (polynom <= 0)
            throw new ArgumentOutOfRangeException(nameof(polynom), "Полином должен быть положительным");

        Dictionary<BigInteger, int> factors = new();

        while (polynom > 1 && polynom.IsEven)
        {
            factors[2] = factors.GetValueOrDefault(2) + 1;
            polynom >>= 1;
        }

        for (BigInteger div = 3; Degree(div) <= (Degree(polynom) >> 1); div += 2)
        {
            while (Remainder(polynom, div).IsZero)
            {
                factors[div] = factors.GetValueOrDefault(div) + 1;
                polynom = Divide(polynom, div);
            }
        }

        if (polynom > 1)
            factors[polynom] = 1;
        return factors;
    }

    private void ValidateMod(byte mod)
    {
        if (!IsIrreducible(mod))
            throw new ArgumentException("Переданный модуль приводим", nameof(mod));
    }

    public byte MultiplyUnchecked(byte a, byte b, byte mod)
    {

        int res = 0;
        int x = a;
        int y = b;
        while (y != 0)
        {
            if ((y & 1) != 0)
                res ^= x;

            bool hasHighBit = (x & 0x80) != 0;
            x = ((x << 1) ^ (hasHighBit ? mod : 0)) & 0xFF;
            y >>= 1;
        }
        return (byte)res;
    }

    private int Degree(BigInteger value) => (int)value.GetBitLength() - 1;

    private BigInteger Remainder(BigInteger dividend, BigInteger divisor)
    {
        if (divisor.IsZero)
            throw new DivideByZeroException();

        int d = Degree(divisor);
        while (!dividend.IsZero && Degree(dividend) >= d)
            dividend ^= divisor << (Degree(dividend) - d);
        return dividend;
    }

    private BigInteger Divide(BigInteger dividend, BigInteger divisor)
    {
        if (divisor.IsZero)
            throw new DivideByZeroException();

        BigInteger quotient = BigInteger.Zero;
        int d = Degree(divisor);
        while (!dividend.IsZero && Degree(dividend) >= d)
        {
            int shift = Degree(dividend) - d;
            quotient ^= BigInteger.One << shift;
            dividend ^= divisor << shift;
        }
        return quotient;
    }
}
