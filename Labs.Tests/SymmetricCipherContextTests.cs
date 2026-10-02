using System.Numerics;
using NUnit.Framework;

namespace Lab1.Tests;

[TestFixture]
public class SymmetricCipherContextTests
{
    private string directory = null!;
    private string InputPath => Path.Combine(directory, "input.bin");
    private string EncryptedPath => Path.Combine(directory, "encrypted.bin");
    private string DecryptedPath => Path.Combine(directory, "decrypted.bin");

    [SetUp]
    public void SetUp()
    {
        directory = Directory.CreateTempSubdirectory("Labs.CipherTests-").FullName;
    }

    [TearDown]
    public void TearDown()
    {
        Directory.Delete(directory, recursive: true);
    }

    [Test]
    public async Task FileOperations_MatchArrayOperationsAcrossBufferBoundaries(
        [Values] CipherMode mode,
        [Values] PaddingMode padding,
        [Values(8, 16)] int blockSize,
        [Values(0, 1, 16, 65520, 65535, 65536, 65537, 131089)] int length)
    {
        byte[] data = CreateData(length);
        var context = CreateContext(new TestCipher(blockSize), mode, padding);
        await File.WriteAllBytesAsync(InputPath, data);

        byte[] arrayEncrypted = await context.EncryptAsync(data);
        await context.EncryptAsync(InputPath, EncryptedPath);
        byte[] fileEncrypted = await File.ReadAllBytesAsync(EncryptedPath);

        Assert.That(fileEncrypted.Length, Is.EqualTo(arrayEncrypted.Length));
        // ISO10126 использует случайные байты только в последнем блоке.
        int deterministicLength = padding == PaddingMode.ISO10126
            ? arrayEncrypted.Length - blockSize : arrayEncrypted.Length;
        Assert.That(fileEncrypted[..deterministicLength],
            Is.EqualTo(arrayEncrypted[..deterministicLength]));

        // Проверяем совместимость обоих API в каждом направлении.
        Assert.That(await context.DecryptAsync(fileEncrypted), Is.EqualTo(data));
        await context.DecryptAsync(EncryptedPath, DecryptedPath);
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(data));
        await File.WriteAllBytesAsync(EncryptedPath, arrayEncrypted);
        await context.DecryptAsync(EncryptedPath, DecryptedPath);
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(data));
    }

    [Test]
    public async Task ZerosPadding_RemovesAtMostBlockSizeMinusOneTrailingBytes(
        [Values] CipherMode mode,
        [Values(8, 16)] int blockSize,
        [Values(0, 65531)] int nonZeroLength,
        [Values(131072, 131088)] int length)
    {
        // Длина кратна блоку: набивка при шифровании не добавляется.
        // Длинный нулевой хвост сохраняется, кроме последних BlockSize - 1 байт.
        byte[] data = new byte[length];
        CreateData(nonZeroLength).CopyTo(data, 0);
        byte[] expected = data[..^(blockSize - 1)];
        var context = CreateContext(new TestCipher(blockSize), mode, PaddingMode.Zeros);
        await File.WriteAllBytesAsync(InputPath, data);

        await context.EncryptAsync(InputPath, EncryptedPath);
        await context.DecryptAsync(EncryptedPath, DecryptedPath);

        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(expected));
        byte[] encrypted = await File.ReadAllBytesAsync(EncryptedPath);
        Assert.That(await context.DecryptAsync(encrypted), Is.EqualTo(expected));
    }

    [Test]
    public async Task FileEncryption_WritesFirstBufferBeforeEncryptingTheNext()
    {
        var cipher = new TestCipher(8);
        var context = CreateContext(cipher, CipherMode.CBC, PaddingMode.PKCS7);
        await File.WriteAllBytesAsync(InputPath, CreateData(2 * 65536 + 1));
        int calls = 0;
        cipher.OnEncrypt = () =>
        {
            if (++calls == 65536 / cipher.BlockSize + 1)
                Assert.That(new FileInfo(EncryptedPath).Length, Is.EqualTo(65536));
        };

        await context.EncryptAsync(InputPath, EncryptedPath);
        Assert.That(calls, Is.GreaterThan(65536 / cipher.BlockSize));
    }

    [Test]
    public async Task FileDecryption_WritesFirstBufferBeforeDecryptingTheNext()
    {
        var cipher = new TestCipher(8);
        var context = CreateContext(cipher, CipherMode.PCBC, PaddingMode.PKCS7);
        byte[] data = CreateData(2 * 65536 + 1);
        await File.WriteAllBytesAsync(EncryptedPath, await context.EncryptAsync(data));
        int calls = 0;
        cipher.OnDecrypt = () =>
        {
            if (++calls == 65536 / cipher.BlockSize + 1)
                Assert.That(new FileInfo(DecryptedPath).Length, Is.EqualTo(65536));
        };

        await context.DecryptAsync(EncryptedPath, DecryptedPath);
        Assert.That(calls, Is.GreaterThan(65536 / cipher.BlockSize));
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(data));
    }

    [Test]
    public async Task FileOperations_WorkWithRealCiphersAcrossBufferBoundary(
        [Values] CipherMode mode, [Values(false, true)] bool useDeal)
    {
        ISymmetricCipher cipher = useDeal ? new Deal() : new Des();
        var context = CreateContext(cipher, mode, PaddingMode.PKCS7);
        byte[] data = CreateData(65536 + 17);
        await File.WriteAllBytesAsync(InputPath, data);

        byte[] expectedEncrypted = await context.EncryptAsync(data);
        await context.EncryptAsync(InputPath, EncryptedPath);
        Assert.That(await File.ReadAllBytesAsync(EncryptedPath), Is.EqualTo(expectedEncrypted));
        await context.DecryptAsync(EncryptedPath, DecryptedPath);
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(data));
    }

    [Test]
    public async Task FileDecryption_RejectsIncompleteCipherBlockBeforeChangingOutput()
    {
        await File.WriteAllBytesAsync(EncryptedPath, new byte[65537]);
        byte[] existingOutput = { 1, 2, 3 };
        await File.WriteAllBytesAsync(DecryptedPath, existingOutput);
        var context = CreateContext(new TestCipher(8), CipherMode.ECB, PaddingMode.PKCS7);

        Assert.ThrowsAsync<ArgumentException>(() => context.DecryptAsync(EncryptedPath, DecryptedPath));
        Assert.That(await File.ReadAllBytesAsync(DecryptedPath), Is.EqualTo(existingOutput));
    }

    [TestCase(PaddingMode.PKCS7)]
    [TestCase(PaddingMode.AnsiX923)]
    [TestCase(PaddingMode.ISO10126)]
    public async Task FileDecryption_RejectsInvalidFinalPadding(PaddingMode padding)
    {
        var cipher = new TestCipher(8);
        var context = CreateContext(cipher, CipherMode.ECB, padding);
        byte[] data = CreateData(65536 + 8);
        byte[] encrypted = await context.EncryptAsync(data);
        byte[] lastBlock = cipher.Decrypt(encrypted[^8..]);
        lastBlock[^1] = 0;
        cipher.Encrypt(lastBlock).CopyTo(encrypted, encrypted.Length - 8);
        await File.WriteAllBytesAsync(EncryptedPath, encrypted);

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            context.DecryptAsync(EncryptedPath, DecryptedPath));
    }

    private static SymmetricCipherContext CreateContext(
        ISymmetricCipher cipher, CipherMode mode, PaddingMode padding)
    {
        byte[] key = CreateData(cipher.BlockSize);
        byte[] iv = Enumerable.Repeat((byte)0xFF, cipher.BlockSize).ToArray();
        return new SymmetricCipherContext(cipher, key, mode, padding,
            mode == CipherMode.ECB ? null : iv, new BigInteger(257));
    }

    private static byte[] CreateData(int length)
    {
        byte[] data = new byte[length];
        new Random(42).NextBytes(data);
        if (length > 0)
            data[^1] = 1; // Zeros не позволяет отличить конечные нули данных от набивки.
        return data;
    }

    // Быстрое обратимое преобразование для проверки режимов и файлового API.
    // DES и DEAL отдельно проверяются в FileOperations_WorkWithRealCiphersAcrossBufferBoundary.
    private sealed class TestCipher(int blockSize) : ISymmetricCipher
    {
        private byte[] key = null!;
        public int BlockSize => blockSize;
        public Action? OnEncrypt { get; set; }
        public Action? OnDecrypt { get; set; }
        public void SetKey(byte[] value) => key = (byte[])value.Clone();

        public byte[] Encrypt(byte[] block)
        {
            OnEncrypt?.Invoke();
            byte[] result = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
                result[i] = (byte)(block[(i + 1) % BlockSize] ^ key[i]);
            return result;
        }

        public byte[] Decrypt(byte[] block)
        {
            OnDecrypt?.Invoke();
            byte[] result = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
                result[(i + 1) % BlockSize] = (byte)(block[i] ^ key[i]);
            return result;
        }
    }
}
