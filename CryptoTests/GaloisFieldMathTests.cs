// using Xunit;
// using CryptoLib.Algorithms.Rijndael.GaloisField;
// using System.Collections.Generic;

// namespace CryptoTests
// {
//     public class GaloisFieldMathTests
//     {
//         // Стандартный неприводимый полином для AES
//         private const byte AesIrreduciblePolynomial = 0x1B;



//         [Theory]
//         [InlineData(0x53, 0xCA, 0x99)] // Пример из Википедии
//         [InlineData(0x00, 0xFF, 0xFF)]
//         [InlineData(0xAB, 0xAB, 0x00)]
//         public void Add_ShouldReturnCorrectXorResult(byte a, byte b, byte expected)
//         {
//             var result = GaloisFieldMath.Add(a, b);
//             Assert.Equal(expected, result);
//         }

//         [Theory]
//         [InlineData(0x57, 0x83, 0xC1)] // Пример из стандарта FIPS-197
//         [InlineData(0x57, 0x13, 0xFE)]
//         [InlineData(0xAE, 0x01, 0xAE)] // Умножение на 1
//         [InlineData(0xAE, 0x00, 0x00)] // Умножение на 0
//         [InlineData(0x02, 0x8D, 0x01)] // 0x8D - обратный к 0x02
//         public void Multiply_ShouldReturnCorrectProduct(byte a, byte b, byte expected)
//         {
//             var result = GaloisFieldMath.Multiply(a, b, AesIrreduciblePolynomial);
//             Assert.Equal(expected, result);
//         }

//         [Theory]
//         [InlineData(0x01, 0x01)] // Обратный к 1 это 1
//         [InlineData(0x02, 0x8D)]
//         [InlineData(0x53, 0xCA)]
//         [InlineData(0xAE, 0xD2)]
//         public void Inverse_ShouldFindCorrectMultiplicativeInverse(byte element, byte expectedInverse)
//         {
//             var result = GaloisFieldMath.Inverse(element, AesIrreduciblePolynomial);
//             Assert.Equal(expectedInverse, result);
//         }

//         [Fact]
//         public void Inverse_OfZero_ShouldBeZero()
//         {
//             var result = GaloisFieldMath.Inverse(0, AesIrreduciblePolynomial);
//             Assert.Equal(0, result);
//         }

//         [Fact]
//         public void Inverse_Property_A_Times_InverseA_ShouldBe_1()
//         {
//             // Проверим для всех ненулевых элементов
//             for (int i = 1; i < 256; i++)
//             {
//                 byte element = (byte)i;
//                 byte inverse = GaloisFieldMath.Inverse(element, AesIrreduciblePolynomial);
//                 byte product = GaloisFieldMath.Multiply(element, inverse, AesIrreduciblePolynomial);
//                 Assert.Equal(1, product);
//             }
//         }

//         [Fact]
//         public void FindAllIrreduciblePolynomials_ShouldReturnExactly30Polynomials()
//         {
//             // Спойлер в задании говорил, что их должно быть 30
//             var polynomials = GaloisFieldMath.FindAllIrreduciblePolynomials();
//             Assert.Equal(30, polynomials.Count);
//         }



//         [Theory]
//         [InlineData(0x1B, true)]  // Стандартный полином AES
//         [InlineData(0x8D, true)]  // Другой известный неприводимый
//         [InlineData(0x01, false)] // x^8 + 1 = (x+1)^8, приводимый
//         [InlineData(0xC3, true)] // x^8+x^7+x^6+x+1, неприводимый
//         [InlineData(0x83, false)] // x^8+x^7+x+1, ПРИВОДИМЫЙ
//         public void IsIrreducible_ShouldCorrectlyIdentifyPolynomials(byte poly, bool expected)
//         {
//             var result = GaloisFieldMath.IsIrreducible(poly);
//             Assert.Equal(expected, result);
//         }


//         [Fact]
//         public void Multiply_KnownValue_From_FIPS197()
//         {
//             byte result = GaloisFieldMath.Multiply(0x57, 0x83, 0x1B);
//             Assert.Equal(0xC1, result);
//         }
    
//     }
// }