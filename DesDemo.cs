using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace Lab1
{
    public class DesDemo
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

        public static async Task Main()
        {
            Console.WriteLine("=== DES: тестирование массивов байтов ===");
            Console.WriteLine();

            await TestRandomByteArrays();

            Console.WriteLine();
            Console.WriteLine("=== DES: тестирование файлов ===");
            Console.WriteLine();

            string[] files =
            {
                "test.txt",
                "image.jpg",
                "doc1.pdf",
            };

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
            int[] sizes = { 1, 7, 8, 9, 100, 1000 };

            foreach (CipherMode mode in Modes)
            {
                Console.WriteLine($"Mode: {mode}");

                foreach (int size in sizes)
                {
                    byte[] data = CreateRandomBytes(size);
                    byte[] key = CreateRandomBytes(8);
                    byte[]? iv = mode == CipherMode.ECB ? null : CreateRandomBytes(8);


                    BigInteger delta = CreateRandomDelta();

                    var des = new Des();

                    SymmetricCipherContext context = CreateContext(des, key, mode, iv, delta);

                    byte[] encrypted = await context.EncryptAsync(data);
                    byte[] decrypted = await context.DecryptAsync(encrypted);

                    bool success = data.SequenceEqual(decrypted);

                    Console.WriteLine(
                        $"Init size: {size, 5} bytes -> " +
                        $"Encrypted size: {encrypted.Length, 5} bytes -> " +
                        $"{(success ? "OK" : "ERROR")}");
                }

                Console.WriteLine();
            }
        }

        private static async Task TestFile(string inputPath)
        {
            Console.WriteLine($"File: {inputPath}");

            foreach (CipherMode mode in Modes)
            {
                byte[] key = CreateRandomBytes(8);
                byte[]? iv = mode == CipherMode.ECB ? null : CreateRandomBytes(8);

                BigInteger delta = CreateRandomDelta();

                var des = new Des();

                SymmetricCipherContext context = CreateContext(des, key,mode, iv, delta);


                string encryptedPath = $"{inputPath}.{mode}.encrypted";
                string decryptedPath = $"{inputPath}.{mode}.decrypted";

                await context.EncryptAsync(inputPath, encryptedPath);
                await context.DecryptAsync(encryptedPath, decryptedPath);

                byte[] original = await File.ReadAllBytesAsync(inputPath);
                byte[] decrypted = await File.ReadAllBytesAsync(decryptedPath);

                bool success = original.SequenceEqual(decrypted);

                Console.WriteLine($"  {mode,-12}: {(success ? "OK" : "ERROR")}");
            }

            Console.WriteLine();
        }

        private static SymmetricCipherContext CreateContext(ISymmetricCipher cipher,
            byte[] key, CipherMode mode, byte[]? iv, BigInteger delta)
        {
            if (mode == CipherMode.RandomDelta)
                return new SymmetricCipherContext(cipher, key, mode, PaddingMode.PKCS7, iv, delta);

            return new SymmetricCipherContext(cipher, key, mode, PaddingMode.PKCS7, iv);
        }

        private static byte[] CreateRandomBytes(int length)
        {
            byte[] data = new byte[length];

            Random.Shared.NextBytes(data);

            return data;
        }

        private static BigInteger CreateRandomDelta()
        {
            return new BigInteger(Random.Shared.NextInt64(1, long.MaxValue));
        }
    }
}