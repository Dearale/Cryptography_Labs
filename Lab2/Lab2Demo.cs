using System.Diagnostics;
using System.Numerics;
using System.Text;

namespace Lab2;

public static class Lab2Demo
{
    public static void Run(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Лабораторная работа №2. Время указано для отдельных вызовов, без вывода в консоль.");

        switch (args.Length == 0 ? "all" : args[0])
        {
            case "all":
                NumberTheory();
                Primality();
                RsaDemo();
                Wiener();
                break;
            case "1": NumberTheory(); break;
            case "2": Primality(); break;
            case "3": RsaDemo(); break;
            case "4": Wiener(); break;
            default: throw new ArgumentException("Укажите all или номер задания: 1, 2, 3, 4.");
        }
    }

    private static void NumberTheory()
    {
        Console.WriteLine("\nЗадание 1. Теоретико-числовые операции");
        Measure("Символ Лежандра (5 / 11)", () => NumberTheoryService.LegendreSymbol(5, 11));
        Measure("Символ Якоби (1001 / 9907)", () => NumberTheoryService.JacobiSymbol(1001, 9907));
        Measure("НОД Евклида (252, 105)", () => NumberTheoryService.GcdEuclid(252, 105));
        Measure("Расширенный Евклид (240, 46)", () => NumberTheoryService.ExtendedGcd(240, 46),
            result => $"НОД={result.Gcd}, x={result.X}, y={result.Y}, 240x+46y={240 * result.X + 46 * result.Y}");
        Measure("Бинарный НОД (252, 105)", () => NumberTheoryService.GcdBinary(252, 105));
        Measure("7^128 mod 13", () => NumberTheoryService.ModPow(7, 128, 13));
        Measure("Функция Эйлера по определению, n=3600", () => NumberTheoryService.EulerPhiByDefinition(3600));
        Measure("Функция Эйлера по разложению, n=3600", () => NumberTheoryService.EulerPhiByFactorization(3600));
        Measure("Функция Эйлера через ДПФ, n=3600", () => NumberTheoryService.EulerPhiByDft(3600));
        Measure("Функция Кармайкла, n=3600", () => NumberTheoryService.Carmichael(3600));
    }

    private static void Primality()
    {
        Console.WriteLine("\nЗадание 2. Вероятностные тесты простоты, вероятность=0.9999");
        foreach (Rsa.PrimalityTestType type in Enum.GetValues<Rsa.PrimalityTestType>())
        {
            IPrimalityTest test = ProbabilisticPrimalityTest.Create(type);
            foreach (int number in new[] { 2, 3, 17, 21, 97, 561, 104729 })
                Measure($"{type}, n={number}", () => test.IsProbablyPrime(number, 0.9999),
                    result => result ? "вероятно простое" : "составное");
        }
    }

    private static void RsaDemo()
    {
        Console.WriteLine("\nЗадание 3. RSA, простые числа длиной 32 бита");
        Rsa rsa = Measure("Генерация RSA-ключей",
            () => new Rsa(Rsa.PrimalityTestType.MillerRabin, 0.999999999999, 32),
            result => $"n={result.CurrentKeyPair.PublicKey.N}");
        PrintKeys(rsa.CurrentKeyPair);

        BigInteger message = 12345;
        BigInteger ciphertext = Measure("Шифрование числа 12345", () => rsa.Encrypt(message));
        BigInteger decrypted = Measure("Дешифрование числа", () => rsa.Decrypt(ciphertext));
        Require(decrypted == message, "Число после дешифрования не совпало с исходным.");

        string text = "Криптография: RSA, лабораторная №2.";
        var blocks = Measure("Шифрование UTF-8 текста", () => rsa.EncryptString(text), result => $"{result.Count} блоков");
        string restored = Measure("Дешифрование UTF-8 текста", () => rsa.DecryptString(blocks));
        Require(restored == text, "Текст после дешифрования не совпал с исходным.");

        byte[] bytes = { 0, 0, 1, 128, 255, 0, 0, 42, 0, 0 };
        var binaryBlocks = Measure("Шифрование байтов с нулями", () => rsa.Encrypt(bytes), result => $"{result.Count} блоков");
        byte[] restoredBytes = Measure("Дешифрование байтов", () => rsa.Decrypt(binaryBlocks), Convert.ToHexString);
        Require(bytes.AsSpan().SequenceEqual(restoredBytes), "Байты после дешифрования не совпали с исходными.");

        Rsa.KeyPair newPair = Measure("Повторная генерация ключей", rsa.GenerateNewKeyPair,
            result => $"n={result.PublicKey.N}, e={result.PublicKey.E}, d={result.PrivateKey.D}");
        Require((newPair.PublicKey.E * newPair.PrivateKey.D) % newPair.Phi == 1, "Новая ключевая пара некорректна.");
        Console.WriteLine("Проверки RSA пройдены.");
    }

    private static void Wiener()
    {
        Console.WriteLine("\nЗадание 4. Атака Винера");
        var generator = new WienerVulnerableKeyGenerator(Rsa.PrimalityTestType.MillerRabin, 0.999999999999, 32);
        Rsa.KeyPair pair = Measure("Генерация уязвимой пары", generator.GenerateKeyPair,
            result => $"n={result.PublicKey.N}, d={result.PrivateKey.D}");
        PrintKeys(pair);

        var attack = new WienerAttackService();
        WienerAttackResult result = Measure("Атака по открытому ключу", () => attack.Attack(pair.PublicKey),
            value => $"успех={value.Success}, d={value.DecryptExp}, phi={value.Phi}");
        Require(result.Success && result.DecryptExp == pair.PrivateKey.D && result.Phi == pair.Phi,
            "Атака не восстановила параметры уязвимой пары.");

        Console.WriteLine("Подходящие дроби:");
        foreach (WienerConvergent convergent in result.Convergents)
            Console.WriteLine($"  {convergent.Numerator}/{convergent.Denominator}");

        BigInteger message = 12345;
        BigInteger ciphertext = Measure("Шифрование открытым ключом",
            () => NumberTheoryService.ModPow(message, pair.PublicKey.E, pair.PublicKey.N));
        BigInteger decrypted = Measure("Дешифрование найденной экспонентой",
            () => NumberTheoryService.ModPow(ciphertext, result.DecryptExp!.Value, pair.PublicKey.N));
        Require(decrypted == message, "Найденная экспонента не расшифровала сообщение.");
        Console.WriteLine("Проверки атаки Винера пройдены.");
    }

    private static T Measure<T>(string operation, Func<T> action, Func<T, string>? format = null)
    {
        long start = Stopwatch.GetTimestamp();
        T result = action();
        TimeSpan elapsed = Stopwatch.GetElapsedTime(start);
        string? value = format == null ? result?.ToString() : format(result);
        Console.WriteLine($"{operation}: {value}");
        Console.WriteLine($"  Время: {elapsed.TotalMilliseconds:F3} мс");
        return result;
    }

    private static void PrintKeys(Rsa.KeyPair pair)
    {
        Console.WriteLine($"p={pair.P}, q={pair.Q}, phi={pair.Phi}");
        Console.WriteLine($"e={pair.PublicKey.E}, d={pair.PrivateKey.D}");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
