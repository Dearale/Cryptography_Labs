using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Lab2;

public class Rsa
{
    public enum PrimalityTestType
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    public struct PublicKey
    {
        public BigInteger N;
        public BigInteger E;

        public PublicKey(BigInteger n, BigInteger exp)
        {
            N = n;
            E = exp;
        }
    }

    public struct PrivateKey
    {
        public BigInteger N;
        public BigInteger D;

        public PrivateKey(BigInteger n, BigInteger d)
        {
            N = n;
            D = d;
        }
    }

    public struct KeyPair
    {
        public PublicKey PublicKey;
        public PrivateKey PrivateKey;
        public BigInteger P;
        public BigInteger Q;
        public BigInteger Phi;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey, BigInteger p, BigInteger q, BigInteger phi)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            P = p;
            Q = q;
            Phi = phi;
        }
    }

    public struct EncryptedBlock
    {
        public BigInteger Value;
        public int PlaintextLength;

        public EncryptedBlock(BigInteger value, int plaintextLength)
        {
            Value = value;
            PlaintextLength = plaintextLength;
        }
    }

    public class KeyGenerator
    {
        private const int MinPrimeBitLength = 16;
        private double minProbability;
        private int primeBitLength;
        private IPrimalityTest primalityTest;
        private Random random;

        public KeyGenerator(PrimalityTestType testType, double minProbability, int primeBitLength)
        {
            if (minProbability < 0.5 || minProbability >= 1.0)
            {
                throw new ArgumentOutOfRangeException(nameof(minProbability), "Вероятность должна быть от 0.5 до 1.");
            }

            if (primeBitLength < MinPrimeBitLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(primeBitLength), $"Битовая длина должна быть не меньше " + $"{MinPrimeBitLength}.");
            }

            this.minProbability = minProbability;
            this.primeBitLength = primeBitLength;
            primalityTest = ProbabilisticPrimalityTest.Create(testType);
            random = new Random();
        }

        public KeyPair GenerateKeyPair()
        {
            while (true)
            {
                BigInteger p = NumberTheoryService.GeneratePrime(random, primeBitLength, minProbability, primalityTest);
                BigInteger q;

                do
                {
                    q = NumberTheoryService.GeneratePrime(random, primeBitLength, minProbability, primalityTest);
                }
                while (!IsProtectedFromFermatAttack(p, q));
                BigInteger n = p * q;
                BigInteger phi = (p - 1) * (q - 1);

                BigInteger e = 65537;

                BezoutResult bezout = NumberTheoryService.ExtendedGcd(e, phi);

                if (bezout.Gcd != 1)
                    continue;

                BigInteger d = NumberTheoryService.NormalizeMod(bezout.X, phi);

                if (!IsProtectedFromWienerAttack(n, d))
                {
                    continue;
                }

                PublicKey publicKey = new PublicKey(n, e);
                PrivateKey privateKey = new PrivateKey(n, d);

                return new KeyPair(publicKey, privateKey, p, q, phi);
            }
        }

        private bool IsProtectedFromFermatAttack(BigInteger p, BigInteger q)
        {
            return NumberTheoryService.Abs(p - q) >= BigInteger.One << (primeBitLength - 2);
        }

        private bool IsProtectedFromWienerAttack(BigInteger n, BigInteger d)
        {
            return d > NumberTheoryService.IntegerFourthRoot(n) / 3;
        }
    }

    public KeyGenerator Generator;
    public KeyPair CurrentKeyPair;

    public Rsa(PrimalityTestType testType, double minProbability, int primeBitLength)
    {
        Generator = new KeyGenerator(testType, minProbability, primeBitLength);
        CurrentKeyPair = Generator.GenerateKeyPair();
    }

    public KeyPair GenerateNewKeyPair()
    {
        CurrentKeyPair = Generator.GenerateKeyPair();

        return CurrentKeyPair;
    }

    public BigInteger Encrypt(BigInteger message)
    {
        PublicKey key = CurrentKeyPair.PublicKey;

        if (message < 0 || message >= key.N)
        {
            throw new ArgumentOutOfRangeException(nameof(message), "Сообщение должно быть 0 <= m < n.");
        }

        return NumberTheoryService.ModPow(message, key.E, key.N);
    }

    public BigInteger Decrypt(BigInteger ciphertext)
    {
        PrivateKey key = CurrentKeyPair.PrivateKey;

        if (ciphertext < 0 || ciphertext >= key.N)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext), "Зашифрованное сообщение должно быть 0 <= c < n.");
        }

        return NumberTheoryService.ModPow(ciphertext, key.D, key.N);
    }

    public IReadOnlyList<EncryptedBlock> Encrypt(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        List<EncryptedBlock> res = new();

        BigInteger n = CurrentKeyPair.PublicKey.N;

        int blockSize = (int)((n.GetBitLength() - 1) / 8);

        for (int offset = 0; offset < data.Length; offset += blockSize)
        {
            int currentLength = Math.Min(blockSize, data.Length - offset);
            byte[] block = new byte[currentLength];
            Array.Copy(data, offset, block, 0, currentLength);
            BigInteger message = new BigInteger(block, isUnsigned: true, isBigEndian: true);
            BigInteger encrypted = Encrypt(message);
            res.Add(new EncryptedBlock(encrypted, currentLength));
        }

        return res;
    }

    public byte[] Decrypt(IReadOnlyList<EncryptedBlock> blocks)
    {
        ArgumentNullException.ThrowIfNull(blocks);

        List<byte> res = new();

        foreach (EncryptedBlock block in blocks)
        {
            BigInteger message = Decrypt(block.Value);
            byte[] bytes = message.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length < block.PlaintextLength)
            {
                int zeroCount = block.PlaintextLength - bytes.Length;

                for (int i = 0; i < zeroCount; i++)
                    res.Add(0);
            }

            foreach (byte value in bytes)
                res.Add(value);
        }

        return res.ToArray();
    }

    public IReadOnlyList<EncryptedBlock> EncryptString(string text)
    {
        byte[] data = Encoding.UTF8.GetBytes(text);

        return Encrypt(data);
    }

    public string DecryptString(IReadOnlyList<EncryptedBlock> cipher)
    {
        byte[] data = Decrypt(cipher);

        return Encoding.UTF8.GetString(data);
    }
}
