using System.Diagnostics;
using System.Numerics;
using Lab3;

var totalTimer = Stopwatch.StartNew();
var field = new Gf2Service();
var operationTimer = Stopwatch.StartNew();
var irreducibles = field.GetIrreducibles();
operationTimer.Stop();
if (irreducibles.Count != 30 || !irreducibles.Contains(0x1B) || !irreducibles.Contains(0x1D))
    throw new Exception("Ожидалось ровно 30 неприводимых полиномов степени 8.");
Console.WriteLine("Задание 1: неприводимые полиномы степени 8 (30): " +
                  string.Join(" ", irreducibles.Select(v => $"0x{0x100 | v:X3}")));
Console.WriteLine($"Время построения коллекции: {operationTimer.Elapsed.TotalMilliseconds:F3} мс.");

operationTimer.Restart();
byte sum = field.Add(0x57, 0x83);
operationTimer.Stop();
Console.WriteLine($"Задание 1: сумма 0x57 и 0x83 в GF(256): 0x{sum:X2}; время={operationTimer.Elapsed.TotalMilliseconds:F3} мс.");

operationTimer.Restart();
byte product = field.Multiply(0x57, 0x83, 0x1B);
operationTimer.Stop();
Console.WriteLine($"Задание 1: произведение 0x57 и 0x83 в GF(256): 0x{product:X2}; время={operationTimer.Elapsed.TotalMilliseconds:F3} мс.");

operationTimer.Restart();
byte inverse = field.Inverse(0x53, 0x1B);
operationTimer.Stop();
Console.WriteLine($"Задание 1: обратный элемент для 0x53 в GF(256): 0x{inverse:X2}; время={operationTimer.Elapsed.TotalMilliseconds:F3} мс.");

operationTimer.Restart();
var factors = field.Factorize(new BigInteger(0b10101));
operationTimer.Stop();
Console.WriteLine("Задание 1: разложение x^4 + x^2 + 1 на множители (двоичная запись): " +
                  string.Join(" * ", factors.Select(factor => $"({Convert.ToString((int)factor.Key, 2)})^{factor.Value}")) +
                  $"; время={operationTimer.Elapsed.TotalMilliseconds:F3} мс.");

operationTimer.Restart();
try
{
    field.Multiply(0x53, 0xCA, 0x00);
    throw new Exception("При умножении ожидалось исключение для приводимого модуля.");
}
catch (ArgumentException ex)
{
    operationTimer.Stop();
    Console.WriteLine($"Задание 1: приводимый модуль отклонён при умножении (параметр: {ex.ParamName}); " +
                      $"время проверки={operationTimer.Elapsed.TotalMilliseconds:F3} мс.");
}
operationTimer.Restart();
try
{
    field.Inverse(0x53, 0x00);
    throw new Exception("При поиске обратного элемента ожидалось исключение для приводимого модуля.");
}
catch (ArgumentException ex)
{
    operationTimer.Stop();
    Console.WriteLine($"Задание 1: приводимый модуль отклонён при поиске обратного элемента (параметр: {ex.ParamName}); " +
                      $"время проверки={operationTimer.Elapsed.TotalMilliseconds:F3} мс.");
}

var aesVectors = new (string Key, string Plain, string Cipher)[]
{
    ("000102030405060708090A0B0C0D0E0F",
     "00112233445566778899AABBCCDDEEFF",
     "69C4E0D86A7B0430D8CDB78070B4C55A"),
    ("000102030405060708090A0B0C0D0E0F1011121314151617",
     "00112233445566778899AABBCCDDEEFF",
     "DDA97CA4864CDFE06EAF70A0EC0D7191"),
    ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF",
     "8EA2B7CA516745BFEAFC49904B496089")
};
foreach (var (key, plain, expected) in aesVectors)
{
    byte[] keyBytes = Convert.FromHexString(key);
    byte[] plainBytes = Convert.FromHexString(plain);
    var cipher = new Rijndael();

    operationTimer.Restart();
    cipher.SetKey(keyBytes);
    operationTimer.Stop();
    double keyExpansionMs = operationTimer.Elapsed.TotalMilliseconds;

    operationTimer.Restart();
    byte[] encrypted = cipher.Encrypt(plainBytes);
    operationTimer.Stop();
    double encryptionMs = operationTimer.Elapsed.TotalMilliseconds;

    operationTimer.Restart();
    byte[] decrypted = cipher.Decrypt(encrypted);
    operationTimer.Stop();
    double decryptionMs = operationTimer.Elapsed.TotalMilliseconds;

    if (Convert.ToHexString(encrypted) != expected ||
        Convert.ToHexString(decrypted) != plain)
        throw new Exception("Результат AES не совпал с эталонным вектором FIPS-197.");
    Console.WriteLine($"Задание 2: AES-{key.Length * 4}, вектор FIPS-197 — проверка пройдена; " +
                      $"расширение ключа={keyExpansionMs:F3} мс, шифрование={encryptionMs:F3} мс, " +
                      $"расшифрование={decryptionMs:F3} мс.");
}

await Task3Demo.RunAsync(args.Length == 0 ? null : args[0]);
totalTimer.Stop();
Console.WriteLine($"Общее время демонстрации: {totalTimer.Elapsed.TotalMilliseconds:F3} мс.");
