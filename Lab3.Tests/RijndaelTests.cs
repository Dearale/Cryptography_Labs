using System.Numerics;
using System.Security.Cryptography;
using Lab1;
using Lab3;
using NUnit.Framework;
using CipherMode = Lab1.CipherMode;
using PaddingMode = Lab1.PaddingMode;

namespace Lab3.Tests;

[TestFixture]
public class RijndaelTests
{
    [TestCase("000102030405060708090A0B0C0D0E0F", "69C4E0D86A7B0430D8CDB78070B4C55A")]
    [TestCase("000102030405060708090A0B0C0D0E0F1011121314151617", "DDA97CA4864CDFE06EAF70A0EC0D7191")]
    [TestCase("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "8EA2B7CA516745BFEAFC49904B496089")]
    public void Fips197Vectors(string keyHex, string expectedHex)
    {
        byte[] key = Convert.FromHexString(keyHex);
        byte[] plaintext = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        var cipher = new Rijndael();
        cipher.SetKey(key);

        byte[] ciphertext = cipher.Encrypt(plaintext);
        Assert.That(Convert.ToHexString(ciphertext), Is.EqualTo(expectedHex));
        Assert.That(cipher.Decrypt(ciphertext), Is.EqualTo(plaintext));
    }

    [Test]
    public void ForwardAndInverseSBoxesIndependentAndMutuallyInverse()
    {
        foreach (byte modulus in new byte[] { 0x1B, 0x1D })
        {
            var box = new RijndaelSBoxes(new Gf2Service(), modulus);
            if (modulus == 0x1B)
            {
                Assert.That(box.Forward[0], Is.EqualTo(0x63));
                Assert.That(box.Forward[0x53], Is.EqualTo(0xED));
                Assert.That(box.Inverse[0xED], Is.EqualTo(0x53));
            }
            var forward = box.Forward;
            var inverse = box.Inverse;
            Assert.That(forward.Distinct().Count(), Is.EqualTo(256));
            Assert.That(inverse.Distinct().Count(), Is.EqualTo(256));
            for (int i = 0; i < 256; i++)
                Assert.That(inverse[forward[i]], Is.EqualTo(i), $"mod=0x{modulus:X2}, x={i}");
        }
    }

    [Test]
    public void ExpandedFirstAes128RoundKeyMatchesFips197()
    {
        var gf = new Gf2Service();
        var sboxes = new RijndaelSBoxes(gf, 0x1B);
        var expansion = new RijndaelKeyExpansion(4, 0x1B, gf, sboxes);
        var keys = expansion.ExpandKey(Convert.FromHexString("000102030405060708090A0B0C0D0E0F"));
        Assert.That(keys.Length, Is.EqualTo(11));
        Assert.That(Convert.ToHexString(keys[1]),
            Is.EqualTo("D6AA74FDD2AF72FADAA678F1D6AB76FE"));
    }

    [Test]
    public void InPlaceRoundReturnsTheSameArray()
    {
        var gf = new Gf2Service();
        var sboxes = new RijndaelSBoxes(gf, 0x1B);
        var round = new RijndaelRound(4, 0x1B, gf, sboxes);
        byte[] state = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] copy = (byte[])state.Clone();
        byte[] roundKey = new byte[16];
        byte[] returned = round.Encrypt(state, roundKey);
        Assert.That(ReferenceEquals(returned, state), Is.True);
        Assert.That(state, Is.Not.EqualTo(copy));
        byte[] decryptedRoundResult = round.Decrypt(state, roundKey);
        Assert.That(ReferenceEquals(decryptedRoundResult, state), Is.True);
        // The decryption round is scheduled for the reverse full cipher,
        // not designed as the standalone inverse of one encryption round.
    }

    [Test]
    public void AllBlockKeyPairsAndTwoModuliRoundTripWithoutMutatingInput()
    {
        foreach (int blockBits in new[] { 128, 192, 256 })
        foreach (int keyBits in new[] { 128, 192, 256 })
        foreach (byte modulus in new byte[] { 0x1B, 0x1D })
        {
            var rijndael = new Rijndael(blockBits, modulus);
            rijndael.SetKey(RandomNumberGenerator.GetBytes(keyBits / 8));
            byte[] input = RandomNumberGenerator.GetBytes(blockBits / 8);
            byte[] original = (byte[])input.Clone();
            for (int repeat = 0; repeat < 3; repeat++)
            {
                byte[] encrypted = rijndael.Encrypt(input);
                Assert.That(rijndael.Decrypt(encrypted), Is.EqualTo(original));
                Assert.That(input, Is.EqualTo(original));
            }
        }
    }

    [Test]
    public void AllModesAndPaddingsIntegrateWithLab1Context()
    {
        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
        {
            byte[] data = RandomNumberGenerator.GetBytes(51);
            data[^1] = 1; // Zero padding is ambiguous for zero-terminated plaintext.
            var cipher = new Rijndael();
            byte[] key = RandomNumberGenerator.GetBytes(16);
            byte[]? iv = mode == CipherMode.ECB ? null : RandomNumberGenerator.GetBytes(16);
            SymmetricCipherContext context = mode == CipherMode.RandomDelta
                ? new(cipher, key, mode, padding, iv, new BigInteger(17))
                : new(cipher, key, mode, padding, iv);
            byte[] ciphertext = context.EncryptAsync(data).GetAwaiter().GetResult();
            byte[] restored = context.DecryptAsync(ciphertext).GetAwaiter().GetResult();
            Assert.That(restored, Is.EqualTo(data), $"mode={mode}, padding={padding}");
        }
    }

    [Test]
    public async Task FileOperationsWith192BitBlocksMatchArraysAcrossBufferBoundaries(
        [Values] CipherMode mode, [Values] PaddingMode padding)
    {
        string directory = Directory.CreateTempSubdirectory("Labs.RijndaelTests-").FullName;
        try
        {
            byte[] data = RandomNumberGenerator.GetBytes(100003);
            data[^1] = 1;
            var cipher = new Rijndael(192, 0x1D);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[]? iv = mode == CipherMode.ECB ? null : RandomNumberGenerator.GetBytes(24);
            SymmetricCipherContext context = mode == CipherMode.RandomDelta
                ? new(cipher, key, mode, padding, iv, new BigInteger(17))
                : new(cipher, key, mode, padding, iv);
            string inputPath = Path.Combine(directory, "input.bin");
            string encryptedPath = Path.Combine(directory, "encrypted.bin");
            string restoredPath = Path.Combine(directory, "restored.bin");
            await File.WriteAllBytesAsync(inputPath, data);

            byte[] arrayEncrypted = await context.EncryptAsync(data);
            await context.EncryptAsync(inputPath, encryptedPath);
            byte[] fileEncrypted = await File.ReadAllBytesAsync(encryptedPath);
            Assert.That(fileEncrypted.Length, Is.EqualTo(arrayEncrypted.Length));
            int deterministicLength = padding == PaddingMode.ISO10126
                ? arrayEncrypted.Length - cipher.BlockSize : arrayEncrypted.Length;
            Assert.That(fileEncrypted[..deterministicLength],
                Is.EqualTo(arrayEncrypted[..deterministicLength]));
            Assert.That(await context.DecryptAsync(fileEncrypted), Is.EqualTo(data));

            await context.DecryptAsync(encryptedPath, restoredPath);
            Assert.That(await File.ReadAllBytesAsync(restoredPath), Is.EqualTo(data));
            await File.WriteAllBytesAsync(encryptedPath, arrayEncrypted);
            await context.DecryptAsync(encryptedPath, restoredPath);
            Assert.That(await File.ReadAllBytesAsync(restoredPath), Is.EqualTo(data));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public void InvalidConfigurationIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Rijndael(64));
        Assert.Throws<ArgumentException>(() => new Rijndael(128, 0x00));
        var field = new Gf2Service();
        var sboxes = new RijndaelSBoxes(field, 0x1B);
        Assert.Throws<ArgumentException>(() => new RijndaelRound(4, 0x00, field, sboxes));
        var cipher = new Rijndael();
        Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(new byte[16]));
        Assert.Throws<ArgumentException>(() => cipher.SetKey(new byte[20]));
        cipher.SetKey(new byte[16]);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[15]));
    }
}
