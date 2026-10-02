using System;
using System.Collections.Generic;
using System.Text;

namespace Lab1
{
    public static class Utils
    {
        public static byte[] Xor(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                throw new ArgumentException("Размеры массивов должны совпадать");
            }

            byte[] res = new byte[first.Length];

            for (int i = 0; i < first.Length; i++)
            {
                res[i] = (byte)(first[i] ^ second[i]);
            }

            return res;
        }

        public static ulong ToUInt64(byte[] bytes)
        {
            ulong res = 0;

            foreach (byte b in bytes)
            {
                res <<= 8;
                res |= b;
            }

            return res;
        }

        private const ulong ByteMask = (1 << 8) - 1;

        public static byte[] ToBytes(ulong value, int size)
        {
            byte[] res = new byte[size];

            for (int i = size - 1; i >= 0; i--)
            {
                res[i] = (byte)(value & ByteMask);
                value >>= 8;
            }

            return res;
        }

        public static byte[] SwapHalves(byte[] block)
        {
            int halfSize = block.Length / 2;

            byte[] result = new byte[block.Length];

            Array.Copy(block, halfSize, result, 0, halfSize);

            Array.Copy(block, 0, result, halfSize, halfSize);

            return result;
        }
    }
}
