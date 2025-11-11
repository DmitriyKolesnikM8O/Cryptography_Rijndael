using Xunit;
using CryptoLib.Algorithms.Rijndael;
using CryptoLib.Algorithms.Rijndael.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

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
    }
}