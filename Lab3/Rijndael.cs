using Lab1;

namespace Lab3;

public class RijndaelSBoxes
{
    private Gf2Service field;
    private byte mod;
    private Lazy<byte[]> forward;
    private Lazy<byte[]> inverse;

    public byte[] Forward => forward.Value;
    public byte[] Inverse => inverse.Value;

    public RijndaelSBoxes(Gf2Service field, byte mod)
    {
        this.field = field;
        this.mod = mod;
        forward = new Lazy<byte[]>(BuildForward);
        inverse = new Lazy<byte[]>(BuildInverse);
    }
    private static byte RotLeft(byte val, int bits) =>
        (byte)((val << bits) | (val >> (8 - bits)));

    private byte[] BuildForward()
    {
        byte[] res = new byte[256];
        for (int i = 0; i < res.Length; i++)
        {

            byte inv = i == 0 ? (byte)0 : field.Inverse((byte)i, mod);
            res[i] = (byte)(inv ^ RotLeft(inv, 1) ^ RotLeft(inv, 2) ^
                               RotLeft(inv, 3) ^ RotLeft(inv, 4) ^ 0x63);
        }
        return res;
    }

    private byte[] BuildInverse()
    {
        byte[] res = new byte[256];
        for (int i = 0; i < res.Length; i++)
        {
            byte y = (byte)i;
            byte inv = (byte)(RotLeft(y, 1) ^ RotLeft(y, 3) ^ RotLeft(y, 6) ^ 0x05);
            res[i] = inv == 0 ? (byte)0 : field.Inverse(inv, mod);
        }
        return res;
    }
}

public class RijndaelKeyExpansion : IKeyExpansion
{
    private int nb;
    private byte mod;
    private Gf2Service field;
    private RijndaelSBoxes sboxes;

    public RijndaelKeyExpansion(int nb, byte mod, Gf2Service field, RijndaelSBoxes sboxes)
    {
        this.nb = nb;
        this.mod = mod;
        this.field = field;
        this.sboxes = sboxes;
    }

    public byte[][] ExpandKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            throw new ArgumentException("Ключ должен быть 16, 24 или 32 байта");

        int nk = key.Length / 4;
        int nr = Math.Max(nb, nk) + 6;
        int wordCount = nb * (nr + 1);

        byte[] expanded = new byte[wordCount * 4];
        key.CopyTo(expanded, 0);
        byte[] tmp = new byte[4];
        byte rcon = 1;

        for (int i = nk; i < wordCount; i++)
        {
            Array.Copy(expanded, (i - 1) * 4, tmp, 0, 4);
            if (i % nk == 0)
            {
                byte first = tmp[0];
                for (int j = 0; j < 3; j++) tmp[j] = tmp[j + 1];
                tmp[3] = first;

                byte[] box = sboxes.Forward;
                for (int j = 0; j < 4; j++) tmp[j] = box[tmp[j]];

                tmp[0] ^= rcon;

                rcon = field.Multiply(rcon, 2, mod);
            }
            else if (nk == 8 && i % nk == 4)
            {
                byte[] box = sboxes.Forward;
                for (int j = 0; j < 4; j++) tmp[j] = box[tmp[j]];
            }

            int offset = i * 4;
            int prev = (i - nk) * 4;
            for (int j = 0; j < 4; j++)
                expanded[offset + j] = (byte)(expanded[prev + j] ^ tmp[j]);
        }

        int roundKeyBytes = 4 * nb;
        byte[][] keys = new byte[nr + 1][];
        for (int round = 0; round <= nr; round++)
        {
            keys[round] = new byte[roundKeyBytes];
            Array.Copy(expanded, round * roundKeyBytes, keys[round], 0, roundKeyBytes);
        }
        return keys;
    }
}

public class RijndaelRound : IRoundEncryptor
{
    private static readonly byte[,] mixMatrix =
    {
        { 0x02, 0x03, 0x01, 0x01 },
        { 0x01, 0x02, 0x03, 0x01 },
        { 0x01, 0x01, 0x02, 0x03 },
        { 0x03, 0x01, 0x01, 0x02 }
    };

    private static readonly byte[,] inverseMixMatrix =
    {
        { 0x0E, 0x0B, 0x0D, 0x09 },
        { 0x09, 0x0E, 0x0B, 0x0D },
        { 0x0D, 0x09, 0x0E, 0x0B },
        { 0x0B, 0x0D, 0x09, 0x0E }
    };

    private int nb;
    private RijndaelSBoxes sboxes;
    private Gf2Service field;
    private byte mod;

    public RijndaelRound(int nb, byte mod, Gf2Service field, RijndaelSBoxes sboxes)
    {
        ArgumentNullException.ThrowIfNull(field);
        if (!field.IsIrreducible(mod))
            throw new ArgumentException("Переданный модуль приводим", nameof(mod));

        this.nb = nb;
        this.sboxes = sboxes;
        this.field = field;
        this.mod = mod;
    }

    public byte[] Encrypt(byte[] state, byte[] roundKey)
    {
        Validate(state, roundKey);
        EncryptInPlace(state, roundKey);
        return state;
    }

    public byte[] Decrypt(byte[] state, byte[] roundKey)
    {
        Validate(state, roundKey);
        DecryptInPlace(state, roundKey);
        return state;
    }

    public void EncryptInPlace(byte[] state, byte[] key)
    {
        SubBytes(state, inverse: false);
        ShiftRows(state, inverse: false);
        MixColumns(state, inverse: false);
        AddRoundKey(state, key);
    }

    public void EncryptLastInPlace(byte[] state, byte[] key)
    {
        SubBytes(state, inverse: false);
        ShiftRows(state, inverse: false);
        AddRoundKey(state, key);
    }

    public void DecryptInPlace(byte[] state, byte[] key)
    {
        ShiftRows(state, inverse: true);
        SubBytes(state, inverse: true);
        AddRoundKey(state, key);
        MixColumns(state, inverse: true);
    }

    public void DecryptLastInPlace(byte[] state, byte[] key)
    {
        ShiftRows(state, inverse: true);
        SubBytes(state, inverse: true);
        AddRoundKey(state, key);
    }

    public static void AddRoundKey(byte[] state, byte[] key)
    {
        if (state.Length != key.Length)
            throw new ArgumentException("Некорретный размер ключа");
        for (int i = 0; i < state.Length; i++)
            state[i] ^= key[i];
    }

    private void Validate(byte[] block, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(block);
        ArgumentNullException.ThrowIfNull(key);
        if (block.Length != nb * 4 || key.Length != nb * 4)
            throw new ArgumentException("Некорректный размер блока или ключа");
    }

    private void SubBytes(byte[] state, bool inverse)
    {
        byte[] box = inverse ? sboxes.Inverse : sboxes.Forward;
        for (int i = 0; i < state.Length; i++)
            state[i] = box[state[i]];
    }

    private void ShiftRows(byte[] state, bool inverse)
    {

        Span<byte> rowBuffer = stackalloc byte[8];
        for (int row = 1; row < 4; row++)
        {
            int shift = row;
            if (nb == 8 && (row == 2 || row == 3)) shift += 1;

            for (int col = 0; col < nb; col++)
            {
                int from = (col + (inverse ? nb - shift : shift)) % nb;
                rowBuffer[col] = state[4 * from + row];
            }
            for (int col = 0; col < nb; col++)
                state[4 * col + row] = rowBuffer[col];
        }
    }

    private void MixColumns(byte[] state, bool inverse)
    {
        byte[,] matrix = inverse ? inverseMixMatrix : mixMatrix;
        Span<byte> column = stackalloc byte[4];

        for (int col = 0; col < nb; col++)
        {
            int offset = col * 4;
            for (int row = 0; row < 4; row++)
                column[row] = state[offset + row];

            for (int row = 0; row < 4; row++)
            {
                byte res = 0;
                for (int k = 0; k < 4; k++)
                    res = field.Add(res, field.MultiplyUnchecked(matrix[row, k], column[k], mod));

                state[offset + row] = res;
            }
        }
    }

}

public class Rijndael : ISymmetricCipher
{
    private RijndaelKeyExpansion expansion;
    private RijndaelRound round;
    private byte[][]? roundKeys;

    public int BlockSize { get; }

    public Rijndael(int blockSizeBits = 128, byte mod = 0x1B)
    {
        if (blockSizeBits is not (128 or 192 or 256))
            throw new ArgumentOutOfRangeException("Размер блока должен быть 128, 192 или 256 битов");

        Gf2Service field = new();
        if (!field.IsIrreducible(mod))
            throw new ArgumentException("Модуль должен быть неприводимым над GF(2)", nameof(mod));

        BlockSize = blockSizeBits / 8;
        RijndaelSBoxes sboxes = new(field, mod);
        expansion = new RijndaelKeyExpansion(BlockSize / 4, mod, field, sboxes);
        round = new RijndaelRound(BlockSize / 4, mod, field, sboxes);
    }

    public void SetKey(byte[] key) => roundKeys = expansion.ExpandKey(key);

    public byte[] Encrypt(byte[] block)
    {
        byte[][] keys = GetKeysAndValidate(block);
        byte[] state = (byte[])block.Clone();

        RijndaelRound.AddRoundKey(state, keys[0]);
        for (int i = 1; i < keys.Length - 1; i++)
            round.EncryptInPlace(state, keys[i]);
        round.EncryptLastInPlace(state, keys[^1]);

        return state;
    }

    public byte[] Decrypt(byte[] block)
    {
        byte[][] keys = GetKeysAndValidate(block);
        byte[] state = (byte[])block.Clone();

        RijndaelRound.AddRoundKey(state, keys[^1]);
        for (int i = keys.Length - 2; i > 0; i--)
            round.DecryptInPlace(state, keys[i]);
        round.DecryptLastInPlace(state, keys[0]);

        return state;
    }

    private byte[][] GetKeysAndValidate(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize)
            throw new ArgumentException($"Блок должен иметь размер {BlockSize} байтов", nameof(block));
        return roundKeys ?? throw new InvalidOperationException("Перед encrypt/decrypt вызовите SetKey");
    }
}
