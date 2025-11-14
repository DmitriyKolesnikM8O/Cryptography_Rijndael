using Xunit;
using CryptoLib.Algorithms.Rijndael;
using CryptoLib.Algorithms.Rijndael.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection; // для BindingFlags enum

namespace CryptoTests
{
    public class RijndaelCipherTests
    {
        // ЗОЛОТЫЕ ТЕСТОВЫЕ ВЕКТОРЫ ИЗ СТАНДАРТА FIPS-197 (APPENDIX C)

        public static IEnumerable<object[]> Aes128TestData =>
            new List<object[]>
            {
                new object[]
                {
                    "2b7e151628aed2a6abf7158809cf4f3c", // key
                    "3243f6a8885a308d313198a2e0370734", // plaintext
                    "3925841d02dc09fbdc118597196a0b32"  // ciphertext
                }
            };

        public static IEnumerable<object[]> Aes192TestData =>
            new List<object[]>
            {
                new object[]
                {
                    // KEY:
                    "000102030405060708090a0b0c0d0e0f1011121314151617",
                    // PLAINTEXT:
                    "00112233445566778899aabbccddeeff",
                    // EXPECTED CIPHERTEXT:
                    "dda97ca4864cdfe06eaf70a0ec0d7191"
                }
            };

        public static IEnumerable<object[]> Aes256TestData =>
            new List<object[]>
            {
                new object[]
                {
                    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                    "6bc1bee22e409f96e93d7e117393172a",
                    "f3eed1bdb5d2a03c064b5a7e3db181f8"
                }
            };

        [Theory]
        [MemberData(nameof(Aes128TestData))]
        [MemberData(nameof(Aes192TestData))]
        [MemberData(nameof(Aes256TestData))]
        public void Encrypt_Decrypt_Roundtrip_Matches_FIPS197_Vectors(string keyHex, string plaintextHex, string expectedCiphertextHex)
        {
            // Arrange
            var key = FromHexString(keyHex);
            var plaintext = FromHexString(plaintextHex);
            var expectedCiphertext = FromHexString(expectedCiphertextHex);

            var keySize = (KeySize)(key.Length * 8);
            var blockSize = (BlockSize)(plaintext.Length * 8);


            var cipher = new RijndaelCipher(keySize, blockSize);

            // Act & Assert: Encryption
            cipher.SetRoundKeys(key);
            var actualCiphertext = cipher.EncryptBlock(plaintext);


            Assert.Equal(expectedCiphertext.ToList(), actualCiphertext.ToList());

            // Act & Assert: Decryption (Roundtrip)
            var decryptedText = cipher.DecryptBlock(actualCiphertext);
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        [Fact]
        public void SetRoundKeys_WithInvalidKeySize_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var wrongKey = new byte[15]; // Должно быть 16

            Assert.Throws<ArgumentException>(() => cipher.SetRoundKeys(wrongKey));
        }

        [Fact]
        public void EncryptBlock_Before_SetRoundKeys_ShouldThrowInvalidOperationException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var block = new byte[16];

            Assert.Throws<InvalidOperationException>(() => cipher.EncryptBlock(block));
        }

        [Fact]
        public void EncryptBlock_WithInvalidBlockSize_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            cipher.SetRoundKeys(new byte[16]);
            var wrongBlock = new byte[15]; // Должно быть 16

            Assert.Throws<ArgumentException>(() => cipher.EncryptBlock(wrongBlock));
        }

        /// <summary>
        /// Вспомогательный метод для преобразования HEX-строки в массив байт.
        /// </summary>
        private byte[] FromHexString(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        [Fact]
        public void SBox_Constructor_WithReduciblePolynomial_ShouldThrowArgumentException()
        {
            // Arrange
            // Полином 0x01 (x^8 + 1) является приводимым, так как (x+1)^8
            byte reduciblePolynomial = 0x01;

            // Act & Assert
            // Проверяем, что конструктор SBox выбросит исключение ArgumentException
            Assert.Throws<ArgumentException>(() => new SBox(reduciblePolynomial));
        }

        [Fact]
        public void RijndaelCipher_Constructor_WithReduciblePolynomial_ShouldThrowArgumentException()
        {
            // Arrange
            // Так как RijndaelCipher внутри себя создает SBox, он должен "пробросить"
            // исключение от конструктора SBox.
            byte reduciblePolynomial = 0x01;
            var keySize = KeySize.K128;
            var blockSize = BlockSize.B128;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new RijndaelCipher(keySize, blockSize, reduciblePolynomial));
        }

        [Theory]
        [MemberData(nameof(Aes128TestData))]
        [MemberData(nameof(Aes192TestData))]
        [MemberData(nameof(Aes256TestData))]
        public void Decrypt_Matches_FIPS197_Vectors(string keyHex, string plaintextHex, string expectedCiphertextHex)
        {
            // Arrange
            var key = FromHexString(keyHex);
            var expectedPlaintext = FromHexString(plaintextHex);
            var ciphertext = FromHexString(expectedCiphertextHex);

            var keySize = (KeySize)(key.Length * 8);
            var blockSize = (BlockSize)(ciphertext.Length * 8);

            var cipher = new RijndaelCipher(keySize, blockSize);

            // Act
            cipher.SetRoundKeys(key);
            var actualPlaintext = cipher.DecryptBlock(ciphertext);

            // Assert
            Assert.Equal(expectedPlaintext.ToList(), actualPlaintext.ToList());
        }

        [Theory]
        // Rijndael-специфичные комбинации (KeySize / BlockSize)
        [InlineData(KeySize.K128, BlockSize.B192)]
        [InlineData(KeySize.K128, BlockSize.B256)]
        [InlineData(KeySize.K192, BlockSize.B256)]
        [InlineData(KeySize.K256, BlockSize.B192)]
        [InlineData(KeySize.K256, BlockSize.B256)]
        // Стандартные AES комбинации для полноты картины
        [InlineData(KeySize.K128, BlockSize.B128)]
        [InlineData(KeySize.K192, BlockSize.B128)]
        [InlineData(KeySize.K256, BlockSize.B128)]
        public void Encrypt_Decrypt_Roundtrip_ShouldWorkForAllSupportedSizes(KeySize keySize, BlockSize blockSize)
        {
            // Arrange
            int keySizeBytes = (int)keySize / 8;
            int blockSizeBytes = (int)blockSize / 8;

            // Генерируем случайный ключ и блок нужного размера
            var key = new byte[keySizeBytes];
            var plaintext = new byte[blockSizeBytes];
            new Random().NextBytes(key);
            new Random().NextBytes(plaintext);

            var cipher = new RijndaelCipher(keySize, blockSize);

            // Act: Encrypt
            cipher.SetRoundKeys(key);
            var ciphertext = cipher.EncryptBlock(plaintext);

            // Act: Decrypt
            // SetRoundKeys нужно вызвать снова, так как в реальном сценарии это могут быть разные экземпляры
            cipher.SetRoundKeys(key);
            var decryptedText = cipher.DecryptBlock(ciphertext);

            // Assert
            // Проверяем, что после шифрования и дешифрования мы вернулись к исходному блоку
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        [Theory]
        // Таблица 5 из оригинальной спецификации "The Design of Rijndael"
        // Nr = max(Nk, Nb) + 6
        // Nk = KeyWords, Nb = BlockWords
        // Nk/Nb | 4    | 6    | 8
        // ------|------|------|------
        // 4     | 10   | 12   | 14
        // 6     | 12   | 12   | 14
        // 8     | 14   | 14   | 14
        [InlineData(KeySize.K128, BlockSize.B128, 10)] // AES-128
        [InlineData(KeySize.K128, BlockSize.B192, 12)]
        [InlineData(KeySize.K128, BlockSize.B256, 14)]
        [InlineData(KeySize.K192, BlockSize.B128, 12)] // AES-192
        [InlineData(KeySize.K192, BlockSize.B192, 12)]
        [InlineData(KeySize.K192, BlockSize.B256, 14)]
        [InlineData(KeySize.K256, BlockSize.B128, 14)] // AES-256
        [InlineData(KeySize.K256, BlockSize.B192, 14)]
        [InlineData(KeySize.K256, BlockSize.B256, 14)]
        public void RijndaelCipher_Constructor_ShouldSetCorrectNumberOfRounds(KeySize keySize, BlockSize blockSize, int expectedRounds)
        {
            // Arrange
            var cipher = new RijndaelCipher(keySize, blockSize);

            // Act
            // Используем рефлексию, чтобы получить значение private readonly поля _rounds
            var field = typeof(RijndaelCipher).GetField("_rounds", BindingFlags.NonPublic | BindingFlags.Instance);
            if (field == null)
                throw new InvalidOperationException("Не удалось найти приватное поле _rounds.");

            var actualRounds = (int)field.GetValue(cipher);

            // Assert
            Assert.Equal(expectedRounds, actualRounds);
        }

        [Theory]
        [InlineData((byte)0x1B)] // Стандартный полином AES
        [InlineData((byte)0x8D)] // Другой валидный неприводимый полином (x^8+x^7+x^3+x^2+1)
        public void Encrypt_Decrypt_Roundtrip_WithCustomPolynomial_ShouldBeReversible(byte irreduciblePolynomial)
        {
            // Arrange
            var keySize = KeySize.K128;
            var blockSize = BlockSize.B128;

            int keySizeBytes = (int)keySize / 8;
            int blockSizeBytes = (int)blockSize / 8;

            var key = new byte[keySizeBytes];
            var plaintext = new byte[blockSizeBytes];
            new Random().NextBytes(key);
            new Random().NextBytes(plaintext);

            // Создаем шифр с заданным полиномом
            var cipher = new RijndaelCipher(keySize, blockSize, irreduciblePolynomial);

            // Act: Encrypt
            cipher.SetRoundKeys(key);
            var ciphertext = cipher.EncryptBlock(plaintext);

            // Act: Decrypt
            // Для дешифрования нужен экземпляр с ТЕМ ЖЕ полиномом
            var decryptCipher = new RijndaelCipher(keySize, blockSize, irreduciblePolynomial);
            decryptCipher.SetRoundKeys(key);
            var decryptedText = decryptCipher.DecryptBlock(ciphertext);

            // Assert
            // Проверяем, что шифр остается обратимым, независимо от выбранного (валидного) полинома
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        #region Exception Handling Tests

        [Fact]
        public void DecryptBlock_Before_SetRoundKeys_ShouldThrowInvalidOperationException()
        {
            // Arrange
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var block = new byte[16];

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => cipher.DecryptBlock(block));
        }

        [Fact]
        public void SetRoundKeys_WithNullKey_ShouldThrowArgumentException()
        {
            // Arrange
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            byte[] nullKey = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => cipher.SetRoundKeys(nullKey));
        }

        [Fact]
        public void EncryptBlock_WithNullBlock_ShouldThrowArgumentException()
        {
            // Arrange
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            cipher.SetRoundKeys(new byte[16]);
            byte[] nullBlock = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => cipher.EncryptBlock(nullBlock));
        }

        [Fact]
        public void DecryptBlock_WithInvalidBlockSize_ShouldThrowArgumentException()
        {
            // Arrange
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            cipher.SetRoundKeys(new byte[16]);
            var wrongBlock = new byte[15]; // Должно быть 16

            // Act & Assert
            Assert.Throws<ArgumentException>(() => cipher.DecryptBlock(wrongBlock));
        }

        [Fact]
        public void RijndaelCipher_Constructor_WithInvalidEnum_ShouldThrowException()
        {
            // Этот тест проверяет, что конструктор и GetNumberOfRounds имеют защиту
            // от невалидных значений enum, если такие можно создать.

            // Arrange
            KeySize invalidKeySize = (KeySize)999;
            BlockSize validBlockSize = BlockSize.B128;

            // Act & Assert
            // Мы ожидаем любое исключение, так как это нештатная ситуация.
            // Скорее всего, это будет InvalidOperationException из GetNumberOfRounds.
            Assert.Throws<InvalidOperationException>(() => new RijndaelCipher(invalidKeySize, validBlockSize));
        }

        #endregion

        #region Boundary Value Tests

        public static IEnumerable<object[]> BoundaryTestData()
        {
            var allZeros = new byte[16]; // Заполнен нулями по умолчанию
            var allOnes = Enumerable.Repeat((byte)0xFF, 16).ToArray();
            var pattern = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

            yield return new object[] { allZeros, "All Zeros Block" };
            yield return new object[] { allOnes, "All Ones Block" };
            yield return new object[] { pattern, "Pattern Block (00 to 0F)" };
        }

        [Theory]
        [MemberData(nameof(BoundaryTestData))]
        public void Encrypt_Decrypt_Roundtrip_WithBoundaryValues_ShouldBeReversible(byte[] plaintext, string description)
        {
            // Arrange
            _ = description; // Используется xUnit для отображения имени теста
            var keySize = KeySize.K128;
            var blockSize = BlockSize.B128;

            var key = new byte[16];
            new Random().NextBytes(key);

            var cipher = new RijndaelCipher(keySize, blockSize);

            // Act
            cipher.SetRoundKeys(key);
            var ciphertext = cipher.EncryptBlock(plaintext);
            var decryptedText = cipher.DecryptBlock(ciphertext);

            // Assert
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        #endregion
        
        [Theory]
        [InlineData(KeySize.K128, BlockSize.B128)]
        [InlineData(KeySize.K192, BlockSize.B128)]
        [InlineData(KeySize.K256, BlockSize.B128)]
        [InlineData(KeySize.K128, BlockSize.B192)]
        [InlineData(KeySize.K192, BlockSize.B192)]
        [InlineData(KeySize.K256, BlockSize.B192)]
        [InlineData(KeySize.K128, BlockSize.B256)]
        [InlineData(KeySize.K192, BlockSize.B256)]
        [InlineData(KeySize.K256, BlockSize.B256)]
        public void Encrypt_Decrypt_Roundtrip_WithSeparateInstances_ShouldBeReversible(KeySize keySize, BlockSize blockSize)
        {
            // Arrange
            int keySizeBytes = (int)keySize / 8;
            int blockSizeBytes = (int)blockSize / 8;

            var key = new byte[keySizeBytes];
            var plaintext = new byte[blockSizeBytes];
            new Random().NextBytes(key);
            new Random().NextBytes(plaintext);

            // Создаем ДВА РАЗНЫХ экземпляра шифра с одинаковыми параметрами
            var encryptCipher = new RijndaelCipher(keySize, blockSize);
            var decryptCipher = new RijndaelCipher(keySize, blockSize);

            // Act
            encryptCipher.SetRoundKeys(key);
            var ciphertext = encryptCipher.EncryptBlock(plaintext);
            
            decryptCipher.SetRoundKeys(key);
            var decryptedText = decryptCipher.DecryptBlock(ciphertext);

            // Assert
            // Проверяем, что результат, полученный одним экземпляром,
            // может быть успешно расшифрован другим.
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }
    }
}