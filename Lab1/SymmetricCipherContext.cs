using System;
using System.Collections.Generic;
using System.Drawing;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace Lab1
{
    public enum CipherMode
    {
        ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
    }

    public enum PaddingMode
    {
        Zeros, AnsiX923, PKCS7, ISO10126
    }

    public class SymmetricCipherContext
    {
        private ISymmetricCipher cipher;
        private CipherMode mode;
        private PaddingMode padding;
        private byte[]? iv;
        private object[] modeArgs;

        private const int byteMask = (1 << 8) - 1;
        private const int FileBufferSize = 64 * 1024;

        private sealed class OperationState
        {
            public byte[] Previous;
            public byte[] PreviousPlain;
            public long BlockIndex;

            public OperationState(byte[]? iv, int blockSize)
            {
                Previous = iv == null ? new byte[blockSize] : (byte[])iv.Clone();
                PreviousPlain = new byte[blockSize];
            }
        }

        public SymmetricCipherContext(ISymmetricCipher cipher, byte[] key, CipherMode mode, 
                                        PaddingMode padding, byte[]? iv = null, params object[] modeArgs)
        {
            if (cipher == null)
                throw new ArgumentNullException(nameof(cipher));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            this.cipher = cipher;
            this.mode = mode;
            this.padding = padding;
            this.iv = iv == null ? null : (byte[])iv.Clone();

            this.modeArgs = modeArgs ?? Array.Empty<object>();
            cipher.SetKey(key);
            ValidateParams();
        }

        private void ValidateParams()
        {
            if (cipher.BlockSize <= 0)
                throw new ArgumentException("Размер блока должен быть больше нуля.");

            if (mode != CipherMode.ECB)
            {
                if (iv == null)
                    throw new ArgumentException("Для данного режима необходим IV.");

                if (iv.Length != cipher.BlockSize)
                    throw new ArgumentException($"Размер IV должен быть равен {cipher.BlockSize} байт");
            }
        }

        public Task<byte[]> EncryptAsync(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            return Task.Run(() => Encrypt(data));
        }

        public Task<byte[]> DecryptAsync(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            return Task.Run(() => Decrypt(data));
        }

        public async Task EncryptAsync(string inputPath, string outputPath)
        {
            await using FileStream input = OpenInputFile(inputPath);
            await using FileStream output = OpenOutputFile(outputPath);

            byte[] buffer = new byte[FileBufferSize];
            var state = new OperationState(iv, cipher.BlockSize);

            while (true)
            {
                int bytesRead = await input.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false);
                bool isFinal = bytesRead < buffer.Length;
                byte[] data = isFinal ? ApplyPadding(buffer[..bytesRead]) : buffer;

                byte[] encrypted = await Task.Run(() => TransformBlocks(data, false, state));
                await output.WriteAsync(encrypted);

                if (isFinal)
                    break;
            }
        }

        public async Task DecryptAsync(string inputPath, string outputPath)
        {
            await using FileStream input = OpenInputFile(inputPath);

            if (input.Length % cipher.BlockSize != 0)
                throw new ArgumentException("Размер зашифрованных данных должен быть кратен размеру блока");

            await using FileStream output = OpenOutputFile(outputPath);
            byte[] buffer = new byte[FileBufferSize];
            var state = new OperationState(iv, cipher.BlockSize);

            while (true)
            {
                int bytesRead = await input.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false);
                if (bytesRead == 0)
                    break;

                byte[] data = bytesRead == buffer.Length ? buffer : buffer[..bytesRead];
                byte[] decrypted = await Task.Run(() => TransformBlocks(data, true, state));

                if (input.Position == input.Length)
                {
                    decrypted = RemovePadding(decrypted);
                }

                await output.WriteAsync(decrypted);
            }
        }

        private static FileStream OpenInputFile(string path) => new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        private static FileStream OpenOutputFile(string path) => new FileStream(
            path, FileMode.Create, FileAccess.Write, FileShare.None, FileBufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        private byte[] Encrypt(byte[] data)
        {
            byte[] paddedData = ApplyPadding(data);
            return TransformBlocks(paddedData, false, new OperationState(iv, cipher.BlockSize));
        }

        private byte[] Decrypt(byte[] data)
        {
            if (data.Length % cipher.BlockSize != 0)
                throw new ArgumentException("Размер зашифрованных данных должен быть кратен размеру блока");

            byte[] decrypted = TransformBlocks(data, true, new OperationState(iv, cipher.BlockSize));
            return RemovePadding(decrypted);
        }

        private byte[] TransformBlocks(byte[] data, bool decrypt, OperationState state)
        {
            byte[] result = mode switch
            {
                CipherMode.ECB => decrypt ? DecryptECB(data) : EncryptECB(data),
                CipherMode.CBC => decrypt ? DecryptCBC(data, state) : EncryptCBC(data, state),
                CipherMode.PCBC => decrypt ? DecryptPCBC(data, state) : EncryptPCBC(data, state),
                CipherMode.CFB => decrypt ? DecryptCFB(data, state) : EncryptCFB(data, state),
                CipherMode.OFB => CryptOFB(data, state),
                CipherMode.CTR => CryptCTR(data, state),
                CipherMode.RandomDelta => CryptRandomDelta(data, state),

                _ => throw new ArgumentOutOfRangeException()
            };

            state.BlockIndex += data.Length / cipher.BlockSize;
            return result;
        }

        private byte[] EncryptECB(byte[] data)
        {
            byte[] res = new byte[data.Length];

            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * cipher.BlockSize;

                byte[] block = GetBlock(data, offset);

                byte[] encrypted = cipher.Encrypt(block);

                WriteBlock(res, encrypted, offset);
            });

            return res;
        }

        private byte[] DecryptECB(byte[] data)
        {
            byte[] res = new byte[data.Length];

            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * cipher.BlockSize;

                byte[] block = GetBlock(data, offset);

                byte[] decrypted = cipher.Decrypt(block);

                WriteBlock(res, decrypted, offset);
            });

            return res;
        }

        private byte[] EncryptCBC(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            byte[] previous = state.Previous;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] block = GetBlock(data, offset);
                byte[] xored = Utils.Xor(block, previous);
                byte[] encrypted = cipher.Encrypt(xored);

                WriteBlock(res, encrypted, offset);

                previous = encrypted;
            }

            state.Previous = previous;
            return res;
        }

        private byte[] DecryptCBC(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;

                byte[] encrypted = GetBlock(data, offset);

                byte[] decrypted = cipher.Decrypt(encrypted);

                byte[] block;
                if (blockIndex == 0)
                {
                    block = Utils.Xor(decrypted, state.Previous);
                } else
                {
                    block = Utils.Xor(decrypted, GetBlock(data, offset - cipher.BlockSize));
                }

                WriteBlock(res, block, offset);
            });

            if (data.Length > 0)
                state.Previous = GetBlock(data, data.Length - cipher.BlockSize);
            return res;
        }

        private byte[] EncryptPCBC(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            byte[] prevPlain = state.PreviousPlain;
            byte[] prevEncrypted = state.Previous;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] plain = GetBlock(data, offset);

                byte[] xored = Utils.Xor(Utils.Xor(plain, prevPlain), prevEncrypted);

                byte[] encrypted = cipher.Encrypt(xored);

                WriteBlock(res, encrypted, offset);

                prevPlain = plain;
                prevEncrypted = encrypted;
            }

            state.PreviousPlain = prevPlain;
            state.Previous = prevEncrypted;
            return res;
        }

        private byte[] DecryptPCBC(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            byte[] prevPlain = state.PreviousPlain;
            byte[] prevEncrypted = state.Previous;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] encrypted = GetBlock(data, offset);
                byte[] decrypted = cipher.Decrypt(encrypted);

                byte[] plain = Utils.Xor(prevEncrypted, Utils.Xor(decrypted, prevPlain));

                WriteBlock(res, plain, offset);

                prevPlain = plain;
                prevEncrypted = encrypted;
            }

            state.PreviousPlain = prevPlain;
            state.Previous = prevEncrypted;
            return res;
        }


        private byte[] EncryptCFB(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            byte[] prev = state.Previous;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] prevEncrypted = cipher.Encrypt(prev);

                byte[] plain = GetBlock(data, offset);

                byte[] encrypted = Utils.Xor(plain, prevEncrypted);

                WriteBlock(res, encrypted, offset);

                prev = encrypted;
            }

            state.Previous = prev;
            return res;
        }

        private byte[] DecryptCFB(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            int blockCount = data.Length / cipher.BlockSize;
            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;

                byte[] encrypted = GetBlock(data, offset);

                byte[] prev;
                if (blockIndex == 0)
                {
                    prev = state.Previous;
                } else
                {
                    prev = GetBlock(data, offset - cipher.BlockSize);
                }

                byte[] prevEncrypted = cipher.Encrypt(prev);
                byte[] plain = Utils.Xor(prevEncrypted, encrypted);
                WriteBlock(res, plain, offset);
            });

            if (data.Length > 0)
                state.Previous = GetBlock(data, data.Length - cipher.BlockSize);
            return res;
        }


        private byte[] CryptOFB(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            byte[] prevEncrypted = state.Previous;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                prevEncrypted = cipher.Encrypt(prevEncrypted);

                byte[] block = GetBlock(data, offset);

                byte[] encrypted = Utils.Xor(block, prevEncrypted);

                WriteBlock(res, encrypted, offset);
            }

            state.Previous = prevEncrypted;
            return res;
        }

        private byte[] CryptCTR(byte[] data, OperationState state)
        {
            byte[] res = new byte[data.Length];

            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;

                byte[] counter = CreateCounter(state.BlockIndex + blockIndex);

                byte[] counterEncrypted = cipher.Encrypt(counter);

                byte[] block = GetBlock(data, offset);

                byte[] output = Utils.Xor(block, counterEncrypted);

                WriteBlock(res, output, offset);
            });

            return res;
        }

        private byte[] CryptRandomDelta(byte[] data, OperationState state)
        {
            if (modeArgs.Length == 0 || modeArgs[0] is not BigInteger delta)
                throw new ArgumentException("Для RandomDelta первым доп параметром должен быть BigInteger delta");

            byte[] res = new byte[data.Length];
            
            BigInteger iv = new BigInteger(this.iv, isUnsigned: true);
            int blockCount = data.Length / cipher.BlockSize;
            Parallel.For(0, blockCount, i =>
            {
                BigInteger counter = iv + new BigInteger(state.BlockIndex + i) * delta;

                byte[] block = counter.ToByteArray(isUnsigned: true);

                Array.Resize(ref block, cipher.BlockSize);

                byte[] encrypted = cipher.Encrypt(block);

                int offset = i * cipher.BlockSize;

                for (int j = 0; j < cipher.BlockSize; j++)
                {
                    res[offset + j] = (byte)(data[offset + j] ^ encrypted[j]);
                }
            });

            return res;
        }

        private byte[] CreateCounter(long blockIndex)
        {
            byte[] counter = (byte[])iv!.Clone();

            long carry = blockIndex;
            for (int i = 0; i < counter.Length && carry > 0; i++)
            {
                long sum = counter[i] + (carry & byteMask);

                counter[i] = (byte)sum;

                carry = (carry >> 8) + (sum >> 8);
            }

            return counter;
        }

        private byte[] ApplyPadding(byte[] data)
        {
            int blockSize = cipher.BlockSize;

            int remainder = data.Length % blockSize;

            int paddingSize;

            if (padding == PaddingMode.Zeros)
            {
                paddingSize = remainder == 0 ? 0 : blockSize - remainder;
            } else
            {
                paddingSize = remainder == 0 ? blockSize : (blockSize - remainder);
            }

            byte[] res = new byte[data.Length + paddingSize];

            Array.Copy(data, res, data.Length);

            if (paddingSize == 0)
                return res;

            switch (padding)
            {
                case PaddingMode.Zeros:
                    break;
                case PaddingMode.AnsiX923:
                    res[^1] = (byte)paddingSize;
                    break;
                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < res.Length; i++)
                    {
                        res[i] = (byte)paddingSize;
                    }
                    break;
                case PaddingMode.ISO10126:
                    if (paddingSize > 1)
                    {
                        Random.Shared.NextBytes(res.AsSpan(data.Length, paddingSize - 1));
                    }
                    res[^1] = (byte)paddingSize;

                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            return res;
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (data.Length == 0)
                return data;

            switch (padding)
            {
                case PaddingMode.Zeros:
                    return RemoveZerosPadding(data);
                case PaddingMode.AnsiX923:
                    return RemoveAnsiX923Padding(data);
                case PaddingMode.PKCS7:
                    return RemovePKCS7Padding(data);
                case PaddingMode.ISO10126:
                    return RemoveISO10126Padding(data);
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private byte[] RemoveZerosPadding(byte[] data)
        {
            int len = data.Length;

            while (len > 0 && data[len - 1] == 0 && data.Length - len < cipher.BlockSize - 1) len--;

            byte[] res = new byte[len];

            Array.Copy(data, res, len);

            return res;
        }

        private byte[] RemoveAnsiX923Padding(byte[] data)
        {
            int paddingSize = data[^1];

            ValidatePaddingSize(data, paddingSize);

            for (int i = data.Length - paddingSize; i < data.Length - 1; i++)
            {
                if (data[i] != 0)
                {
                    throw new InvalidOperationException(
                        "Некорректная ANSI X.923 набивка.");
                }
            }

            return RemoveLastBytes(data, paddingSize);
        }

        private byte[] RemovePKCS7Padding(byte[] data)
        {
            int paddingSize = data[^1];

            ValidatePaddingSize(data, paddingSize);

            for (int i = data.Length - paddingSize; i < data.Length; i++)
            {
                if (data[i] != paddingSize)
                {
                    throw new InvalidOperationException(
                        "Некорректная PKCS7 набивка");
                }
            }

            return RemoveLastBytes(data, paddingSize);
        }

        private byte[] RemoveISO10126Padding(byte[] data)
        {
            int paddingSize = data[^1];

            ValidatePaddingSize(data, paddingSize);

            return RemoveLastBytes(data, paddingSize);
        }

        private void ValidatePaddingSize(byte[] data, int paddingSize)
        {
            if (paddingSize <= 0 ||
                paddingSize > cipher.BlockSize ||
                paddingSize > data.Length)
            {
                throw new InvalidOperationException("Некорректный размер набивки");
            }
        }

        private byte[] RemoveLastBytes(byte[] data, int count)
        {
            int resLen = data.Length - count;

            byte[] res = new byte[resLen];

            Array.Copy(data, res, resLen);

            return res;
        }

        private byte[] GetBlock(byte[] data, int offset)
        {
            byte[] block = new byte[cipher.BlockSize];

            Array.Copy(data, offset, block, 0, cipher.BlockSize);

            return block;
        }

        private void WriteBlock(byte[] dest, byte[] block, int offset)
        {
            Array.Copy(block, 0, dest, offset, block.Length);
        }
    }
}

