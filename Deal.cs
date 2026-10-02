using System;
using System.Collections.Generic;
using System.Text;

namespace Lab1
{
    public class DesRoundAdapter : IRoundEncryptor
    {
        public byte[] Encrypt(byte[] block, byte[] roundKey)
        {
            ArgumentNullException.ThrowIfNull(block);
            ArgumentNullException.ThrowIfNull(roundKey);

            var des = new Des();
            des.SetKey(roundKey);
            return des.Encrypt(block);
        }
    }

    public class DealKeyExpansion : IKeyExpansion
    {
        private static readonly byte[] KeyScheduleDesKey =
        {
            0x12, 0x34, 0x56, 0x78,
            0x90, 0xAB, 0xCD, 0xEF
        };

        private static readonly byte[][] Constants =
        {
            [
                0x80, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ],

            [
                0x40, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ],

            [
                0x20, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ],

            [
                0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        };

        public byte[][] ExpandKey(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);

            int keyPartCount = key.Length / 8;

            int roundCount = key.Length == 32 ? 8 : 6;

            byte[][] keyParts = SplitKey(key);

            byte[][] roundKeys = new byte[roundCount][];

            var des = new Des();

            des.SetKey(KeyScheduleDesKey);

            for (int i = 0; i < roundCount; i++)
            {
                byte[] val = (byte[])keyParts[i % keyPartCount].Clone();

                if (i > 0)
                {
                    XorInPlace(val, roundKeys[i - 1]);
                }

                if (i >= keyPartCount)
                {
                    XorInPlace(val, Constants[i - keyPartCount]);
                }

                roundKeys[i] = des.Encrypt(val);
            }

            return roundKeys;
        }

        private byte[][] SplitKey(byte[] key)
        {
            int partCount = key.Length / 8;

            byte[][] res = new byte[partCount][];

            for (int i = 0; i < partCount; i++)
            {
                res[i] = new byte[8];

                Array.Copy(key, i * 8, res[i], 0, 8);
            }

            return res;
        }
        
        private void XorInPlace(byte[] dest, byte[] other)
        {
            if (dest.Length != other.Length)
                throw new ArgumentException("Размеры блоков должны совпадать");

            for (int i = 0; i < dest.Length; i++)
            {
                dest[i] ^= other[i];
            }
        }
    }

    public class Deal : ISymmetricCipher
    {
        private readonly FeistelNetwork feistel;

        public int BlockSize => 16;

        public Deal()
        {
            feistel = new FeistelNetwork(new DealKeyExpansion(), new DesRoundAdapter(), BlockSize);
        }

        public void SetKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException("Ключ deal должен быть 16, 24 или 32 байта");
            }

            feistel.SetKey(key);
        }

        public byte[] Encrypt(byte[] block)
        {
            ValidateBlock(block);

            byte[] res = feistel.Encrypt(block);

            return Utils.SwapHalves(res);
        }

        public byte[] Decrypt(byte[] block)
        {
            ValidateBlock(block);

            byte[] swapped = Utils.SwapHalves(block);
            return feistel.Decrypt(swapped);
        }

        private void ValidateBlock(byte[] block)
        {
            ArgumentNullException.ThrowIfNull(block);

            if (block.Length != BlockSize)
                throw new ArgumentException("Deal работает с блоками размером 16 байт.");
        }
    }
}
