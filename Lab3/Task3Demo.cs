using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using Lab1;
using CipherMode = Lab1.CipherMode;
using PaddingMode = Lab1.PaddingMode;

namespace Lab3;

public static class Task3Demo
{
    private static readonly int[] Sizes = { 128, 192, 256 };
    private static readonly byte[] Moduli = { 0x1B, 0x1D };

    public static async Task RunAsync(string? samplesDirectory = null)
    {
        var totalTimer = Stopwatch.StartNew();
        var modes = Enum.GetValues<CipherMode>();
        var paddings = Enum.GetValues<PaddingMode>();
        int successful = 0;

        Console.WriteLine("Задание 3: время указано в миллисекундах; для байтов — сумма по шести длинам входа, " +
                          "для файлов — с учётом чтения и записи.");

        foreach (CipherMode mode in modes)
        foreach (PaddingMode padding in paddings)
        {
            int i = successful;
            await CheckBytes(Sizes[i % 3], Sizes[(i / 3) % 3], Moduli[i % 2], mode, padding);
            successful++;
        }

        foreach (int blockBits in Sizes)
        foreach (int keyBits in Sizes)
        foreach (byte modulus in Moduli)
        {
            await CheckBytes(blockBits, keyBits, modulus, CipherMode.CBC, PaddingMode.PKCS7);
            successful++;
        }
        Console.WriteLine($"Задание 3: успешно проверено {successful} конфигураций шифрования байтов.");

        string folder = samplesDirectory ?? Path.Combine(AppContext.BaseDirectory, "Samples");
        if (!Directory.Exists(folder))
            throw new DirectoryNotFoundException("Каталог с примерами не найден: " + folder);

        string[] paths = Directory.GetFiles(folder)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray();
        if (paths.Length == 0)
            throw new InvalidOperationException("Каталог с примерами пуст: " + folder);

        string resultFolder = Path.Combine(folder, "Results");
        Directory.CreateDirectory(resultFolder);

        var safePaddings = new[] { PaddingMode.PKCS7, PaddingMode.AnsiX923, PaddingMode.ISO10126 };
        var operationTimer = new Stopwatch();
        for (int i = 0; i < paths.Length; i++)
        {
            CipherMode mode = modes[(i + 1) % modes.Length];
            PaddingMode padding = safePaddings[i % safePaddings.Length];
            int blockBits = Sizes[i % Sizes.Length];
            int keyBits = Sizes[(i + 1) % Sizes.Length];
            byte modulus = Moduli[i % Moduli.Length];

            var context = MakeContext(blockBits, keyBits, modulus, mode, padding);

            string name = Path.GetFileName(paths[i]);
            long fileSize = new FileInfo(paths[i]).Length;
            string encryptedPath = Path.Combine(resultFolder, name + ".enc");
            string recoveredPath = Path.Combine(resultFolder, "restored_" + name);

            operationTimer.Restart();
            await context.EncryptAsync(paths[i], encryptedPath);
            operationTimer.Stop();
            double encryptionMs = operationTimer.Elapsed.TotalMilliseconds;

            operationTimer.Restart();
            await context.DecryptAsync(encryptedPath, recoveredPath);
            operationTimer.Stop();
            double decryptionMs = operationTimer.Elapsed.TotalMilliseconds;

            if (!await FilesEqual(paths[i], recoveredPath))
                throw new InvalidOperationException("После расшифрования содержимое файла не совпало с исходным: " + name);
            Console.WriteLine($"Файл проверен: {name,-13} размер={fileSize} байт ({fileSize / 1024.0:F2} КиБ), " +
                              $"режим={mode,-12} набивка={padding,-9} " +
                              $"блок={blockBits} бит, ключ={keyBits} бит, модуль=0x{modulus:X2}; " +
                              $"шифрование={encryptionMs:F3} мс, " +
                              $"расшифрование={decryptionMs:F3} мс.");
        }
        Console.WriteLine("Задание 3: все файлы восстановлены побайтно. Результаты: " + resultFolder);
        totalTimer.Stop();
        Console.WriteLine($"Общее время задания 3: {totalTimer.Elapsed.TotalMilliseconds:F3} мс.");
    }

    private static async Task CheckBytes(int blockBits, int keyBits, byte modulus,
                                        CipherMode mode, PaddingMode padding)
    {
        int blockBytes = blockBits / 8;
        var operationTimer = new Stopwatch();
        double encryptionMs = 0;
        double decryptionMs = 0;

        foreach (int length in new[] { 0, 1, blockBytes - 1, blockBytes,
                                       blockBytes + 1, 2 * blockBytes + 5 })
        {
            byte[] data = RandomNumberGenerator.GetBytes(length);
            if (length > 0)
                data[^1] = 1;

            var context = MakeContext(blockBits, keyBits, modulus, mode, padding);

            operationTimer.Restart();
            byte[] encrypted = await context.EncryptAsync(data);
            operationTimer.Stop();
            encryptionMs += operationTimer.Elapsed.TotalMilliseconds;

            operationTimer.Restart();
            byte[] restored = await context.DecryptAsync(encrypted);
            operationTimer.Stop();
            decryptionMs += operationTimer.Elapsed.TotalMilliseconds;

            if (!data.AsSpan().SequenceEqual(restored))
                throw new InvalidOperationException($"Байты после расшифрования не совпали с исходными: {mode}/{padding}, " +
                    $"блок={blockBits} бит, ключ={keyBits} бит, модуль=0x{modulus:X2}, длина={length}");
        }

        Console.WriteLine($"Байты проверены: режим={mode,-12} набивка={padding,-9} " +
                          $"блок={blockBits} бит, ключ={keyBits} бит, модуль=0x{modulus:X2}; " +
                          $"шифрование={encryptionMs:F3} мс, " +
                          $"расшифрование={decryptionMs:F3} мс.");
    }

    private static SymmetricCipherContext MakeContext(int blockBits, int keyBits,
        byte modulus, CipherMode mode, PaddingMode padding)
    {
        byte[] key = RandomNumberGenerator.GetBytes(keyBits / 8);
        byte[]? iv = mode == CipherMode.ECB ? null : RandomNumberGenerator.GetBytes(blockBits / 8);
        var cipher = new Rijndael(blockBits, modulus);

        return mode == CipherMode.RandomDelta
            ? new SymmetricCipherContext(cipher, key, mode, padding, iv, new BigInteger(17))
            : new SymmetricCipherContext(cipher, key, mode, padding, iv);
    }

    private static async Task<bool> FilesEqual(string originalPath, string recoveredPath)
    {
        await using var a = File.OpenRead(originalPath);
        await using var b = File.OpenRead(recoveredPath);
        if (a.Length != b.Length) return false;

        var bufferA = new byte[64 * 1024];
        var bufferB = new byte[bufferA.Length];
        int read;
        while ((read = await a.ReadAsync(bufferA.AsMemory())) != 0)
        {
            await b.ReadExactlyAsync(bufferB.AsMemory(0, read));
            if (!bufferA.AsSpan(0, read).SequenceEqual(bufferB.AsSpan(0, read)))
                return false;
        }
        return true;
    }
}
