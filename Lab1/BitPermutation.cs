using System;
using System.Collections.Generic;

namespace Lab1
{
    public enum BitIndexDirection
    {
        LeastToMostSignificant, MostToLeastSignificant
    }

    public enum BitIndexBase
    {
        Zero = 0, One = 1
    }

    public static class BitPermutation
    {
        public static byte[] Permute(byte[] value, IReadOnlyList<int> pBlock, BitIndexDirection dir, BitIndexBase idxBase)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            if (pBlock == null)
                throw new ArgumentNullException(nameof(pBlock));

            byte[] res = new byte[(pBlock.Count + 7) / 8];

            int valueBitCount = value.Length * 8;
            int baseOffset = (int)idxBase;
            for (int i = 0; i < pBlock.Count; i++)
            {
                int valueBitIdx = pBlock[i] - baseOffset;
                if (valueBitIdx < 0 || valueBitIdx >= valueBitCount)
                {
                    throw new ArgumentOutOfRangeException(nameof(pBlock));
                }

                bool bit = GetBit(value, valueBitIdx, dir);

                SetBit(res, i, dir, bit);
            }

            return res;
        }

        private static bool GetBit(byte[] value, int bitIdx, BitIndexDirection dir)
        {
            (byte mask, int byteIdx) = GetBitMaskAndByteIdx(value, bitIdx, dir);
            return (value[byteIdx] & mask) != 0;
        }

        private static void SetBit(byte[] value, int bitIdx, BitIndexDirection dir, bool bit)
        {
            (byte mask, int byteIdx) = GetBitMaskAndByteIdx(value, bitIdx, dir);
            if (bit)
                value[byteIdx] |= mask;
            else
                value[byteIdx] &= (byte)~mask;
        }

        private static (byte, int) GetBitMaskAndByteIdx(byte[] value, int bitIdx, BitIndexDirection dir)
        {
            int byteOffset = bitIdx / 8;
            int idxInsideByte = bitIdx % 8;

            int byteIdx;
            int physicalBitIdx;
            if (dir == BitIndexDirection.MostToLeastSignificant)
            {
                byteIdx = byteOffset;
                physicalBitIdx = 7 - idxInsideByte;
            } else
            {
                byteIdx = value.Length - 1 - byteOffset;
                physicalBitIdx = idxInsideByte;
            }

            byte mask = (byte)(1 << physicalBitIdx);

            return (mask, byteIdx);
        }
    }
}