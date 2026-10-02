using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace Lab1
{
    public class DealDemo
    {
        private static readonly CipherMode[] Modes =
        {
            CipherMode.ECB,
            CipherMode.CBC,
            CipherMode.PCBC,
            CipherMode.CFB,
            CipherMode.OFB,
            CipherMode.CTR,
            CipherMode.RandomDelta
        };

        private static readonly int[] DealKeySizes = { 16, 24, 32 };

        public static async Task Main()
        {
            Console.WriteLine("=== DEAL: тестирование массивов байтов ===");
            await TestRandomByteArrays();

            Console.WriteLine("\n=== DEAL: тестирование файлов ===");

            string[] files = { "test.txt", "image.jpg", "doc1.pdf" };

            foreach (string file in files)
            {
                if (!File.Exists(file))
                {
                    Console.WriteLine($"Файл {file} не найден, пропускаем.");
                    continue;
                }

                await TestFile(file);
            }
        }

        private static async Task TestRandomByteArrays()
        {
            int[] sizes = { 1, 15, 16, 17, 100, 1000 };

            foreach (int keySize in DealKeySizes)
            {
                Console.WriteLine($"\n========== DEAL-{keySize * 8} ==========");

                foreach (CipherMode mode in Modes)
                {
                    Console.WriteLine($"Mode: {mode}");

                    foreach (int size in sizes)
                    {
                        byte[] data = CreateRandomBytes(size);
                        byte[] key = CreateRandomBytes(keySize);
                        byte[]? iv = mode == CipherMode.ECB ? null : CreateRandomBytes(16);
                        BigInteger delta = CreateRandomDelta();

                        var deal = new Deal();
                        SymmetricCipherContext context = CreateContext(deal, key, mode, iv, delta);

                        var stopwatch = Stopwatch.StartNew();
                        byte[] encrypted = await context.EncryptAsync(data);
                        stopwatch.Stop();
                        double encryptionTimeMs = stopwatch.Elapsed.TotalMilliseconds;

                        stopwatch.Restart();
                        byte[] decrypted = await context.DecryptAsync(encrypted);
                        stopwatch.Stop();
                        double decryptionTimeMs = stopwatch.Elapsed.TotalMilliseconds;

                        bool success = data.SequenceEqual(decrypted);

                        Console.WriteLine(
                            $"  {size,5} bytes -> {encrypted.Length,5} bytes -> {(success ? "OK" : "ERROR")} | " +
                            $"шифрование: {encryptionTimeMs:F3} мс | дешифрование: {decryptionTimeMs:F3} мс");
                    }
                }
            }
        }

        private static async Task TestFile(string inputPath)
        {
            Console.WriteLine($"\nFile: {inputPath}");

            byte[] key = CreateRandomBytes(32);

            foreach (CipherMode mode in Modes)
            {
                byte[]? iv = mode == CipherMode.ECB ? null : CreateRandomBytes(16);
                BigInteger delta = CreateRandomDelta();

                var deal = new Deal();
                SymmetricCipherContext context = CreateContext(deal, key, mode, iv, delta);

                string encryptedPath = $"{inputPath}.{mode}.deal.encrypted";
                string decryptedPath = $"{inputPath}.{mode}.deal.decrypted";

                var stopwatch = Stopwatch.StartNew();
                await context.EncryptAsync(inputPath, encryptedPath);
                stopwatch.Stop();
                double encryptionTimeMs = stopwatch.Elapsed.TotalMilliseconds;

                stopwatch.Restart();
                await context.DecryptAsync(encryptedPath, decryptedPath);
                stopwatch.Stop();
                double decryptionTimeMs = stopwatch.Elapsed.TotalMilliseconds;

                byte[] original = await File.ReadAllBytesAsync(inputPath);
                byte[] decrypted = await File.ReadAllBytesAsync(decryptedPath);

                bool success = original.SequenceEqual(decrypted);

                Console.WriteLine(
                    $"  {mode,-12}: {(success ? "OK" : "ERROR")} | " +
                    $"шифрование: {encryptionTimeMs:F3} мс | дешифрование: {decryptionTimeMs:F3} мс");
            }
        }

        private static SymmetricCipherContext CreateContext(
            ISymmetricCipher cipher, byte[] key, CipherMode mode, byte[]? iv, BigInteger delta)
        {
            if (mode == CipherMode.RandomDelta)
                return new SymmetricCipherContext(cipher, key, mode, PaddingMode.PKCS7, iv, delta);

            return new SymmetricCipherContext(cipher, key, mode, PaddingMode.PKCS7, iv);
        }

        private static byte[] CreateRandomBytes(int length)
        {
            byte[] result = new byte[length];
            Random.Shared.NextBytes(result);
            return result;
        }

        private static BigInteger CreateRandomDelta()
        {
            return new BigInteger(Random.Shared.NextInt64(1, long.MaxValue));
        }
    }
}
