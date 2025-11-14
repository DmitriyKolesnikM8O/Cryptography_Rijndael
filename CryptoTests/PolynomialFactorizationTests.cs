using Xunit;
using CryptoLib.Algorithms.Rijndael.GaloisField;
using System.Collections.Generic;
using System;
using System.Reflection;
using System.Numerics;

namespace CryptoTests
{
    public class PolynomialFactorizationTests
    {
        private static MethodInfo GetPrivateStaticMethod(string methodName, Type[] types)
        {
            var method = typeof(GaloisFieldMath).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static, types);
            if (method == null)
                throw new InvalidOperationException($"Не удалось найти приватный метод {methodName}");
            return method;
        }

        // Вспомогательная функция для парсинга двоичных строк в BigInteger
        private BigInteger FromBinaryString(string s)
        {
            BigInteger result = 0;
            foreach (char c in s)
            {
                result <<= 1;
                if (c == '1')
                    result |= 1;
            }
            return result;
        }

        [Theory]
        [InlineData("1011", 3)]
        [InlineData("1", 0)]
        [InlineData("0", -1)]
        [InlineData("100000000", 8)]
        public void GetPolynomialDegreeBig_ShouldReturnCorrectDegree(string polyStr, int expectedDegree)
        {
            BigInteger poly = FromBinaryString(polyStr); // ИСПРАВЛЕННЫЙ ПАРСИНГ

            var method = GetPrivateStaticMethod("GetPolynomialDegreeBig", new[] { typeof(BigInteger) });
            var result = (int)method.Invoke(null, new object[] { poly });
            Assert.Equal(expectedDegree, result);
        }

        [Theory]
        [InlineData("1101101", "101", "11100", "1")]
        [InlineData("1001", "11", "111", "0")]
        public void PolynomialDivision_ShouldReturnCorrectQuotientAndRemainder(string dividendStr, string divisorStr, string expectedQuotientStr, string expectedRemainderStr)
        {
            BigInteger dividend = FromBinaryString(dividendStr);
            BigInteger divisor = FromBinaryString(divisorStr);
            BigInteger expectedQuotient = FromBinaryString(expectedQuotientStr);
            BigInteger expectedRemainder = FromBinaryString(expectedRemainderStr);

            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        // ... (Аналогичные исправления для остальных тестов) ...

        [Theory]
        [InlineData("1111", "1001", "11")]
        [InlineData("10011", "101", "1")]
        public void PolynomialGcd_ShouldReturnCorrectGcd(string aStr, string bStr, string expectedGcdStr)
        {
            BigInteger a = FromBinaryString(aStr);
            BigInteger b = FromBinaryString(bStr);
            BigInteger expectedGcd = FromBinaryString(expectedGcdStr);

            var method = GetPrivateStaticMethod("PolynomialGcd", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = (BigInteger)method.Invoke(null, new object[] { a, b });
            Assert.Equal(expectedGcd, result);
        }

        [Theory]
        [InlineData("10011", true)]
        [InlineData("111", true)]
        [InlineData("10001", false)]
        [InlineData("110011", false)]
        public void IsIrreducibleBig_ShouldWorkCorrectly(string polyStr, bool expected)
        {
            BigInteger poly = FromBinaryString(polyStr);

            var method = GetPrivateStaticMethod("IsIrreducibleBig", new[] { typeof(BigInteger) });
            var result = (bool)method.Invoke(null, new object[] { poly });
            Assert.Equal(expected, result);
        }

        [Fact]
        public void FactorizePolynomial_ShouldFactorizeCorrectly()
        {
            BigInteger polynomial = FromBinaryString("10000001");
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("11"), 1 },
                { FromBinaryString("1011"), 1 },
                { FromBinaryString("1101"), 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Fact]
        public void FactorizePolynomial_WithRepeatedFactors()
        {
            BigInteger polynomial = FromBinaryString("10001");
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("11"), 4 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(FromBinaryString("11")));
            Assert.Equal(4, actualFactors[FromBinaryString("11")]);
        }

        [Fact]
        public void FactorizePolynomial_WithXAsFactor()
        {
            BigInteger polynomial = FromBinaryString("10010");
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { 2, 1 },
                { FromBinaryString("11"), 1 },
                { FromBinaryString("111"), 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Fact]
        public void PolynomialDivision_WhenDivisorDegreeIsGreater_ShouldReturnZeroQuotient()
        {
            // Arrange
            // Делим p1(x) = x^3 на p2(x) = x^5
            BigInteger dividend = FromBinaryString("1000"); // x^3
            BigInteger divisor = FromBinaryString("100000"); // x^5

            BigInteger expectedQuotient = 0;
            BigInteger expectedRemainder = dividend; // Остаток должен быть равен самому делимому

            // Act
            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });

            // Assert
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void PolynomialDivision_ByOne_ShouldReturnPolynomialAsQuotient()
        {
            // Arrange
            BigInteger dividend = FromBinaryString("1101101"); // p(x)
            BigInteger divisor = 1;

            BigInteger expectedQuotient = dividend;
            BigInteger expectedRemainder = 0;

            // Act
            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });

            // Assert
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void PolynomialDivision_ByItself_ShouldReturnOneAsQuotient()
        {
            // Arrange
            BigInteger polynomial = FromBinaryString("1101101"); // p(x)

            BigInteger expectedQuotient = 1;
            BigInteger expectedRemainder = 0;

            // Act
            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { polynomial, polynomial });

            // Assert
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void PolynomialDivision_ZeroByPolynomial_ShouldReturnZero()
        {
            // Arrange
            BigInteger dividend = 0;
            BigInteger divisor = FromBinaryString("1101101");

            BigInteger expectedQuotient = 0;
            BigInteger expectedRemainder = 0;

            // Act
            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });

            // Assert
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void FactorizePolynomial_OfIrreduciblePolynomial_ShouldReturnItself()
        {
            // Arrange
            // x^4 + x + 1 - известный неприводимый полином
            BigInteger irreduciblePolynomial = FromBinaryString("10011");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { irreduciblePolynomial, 1 }
            };

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(irreduciblePolynomial);

            // Assert
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(irreduciblePolynomial));
            Assert.Equal(1, actualFactors[irreduciblePolynomial]);
        }

        [Fact]
        public void FactorizePolynomial_WithRepeatedIrreducibleFactor()
        {
            // Arrange
            // p(x) = (x^2 + x + 1)^2 = x^4 + x^2 + 1
            BigInteger polynomial = FromBinaryString("10101");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("111"), 2 } // (x^2+x+1) в степени 2
            };

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            // Assert
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(FromBinaryString("111")));
            Assert.Equal(2, actualFactors[FromBinaryString("111")]);
        }

        [Fact]
        public void FactorizePolynomial_WithMixedFactorsAndPowers()
        {
            // Arrange
            // p(x) = x * (x+1)^2 * (x^2+x+1)
            // (x+1)^2 = x^2+1
            // x * (x^2+1) * (x^2+x+1) = (x^3+x) * (x^2+x+1) = x^5+x^4+x^2+x
            BigInteger polynomial = FromBinaryString("110110");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { 2, 1 },                       // x
                { FromBinaryString("11"), 2 },  // (x+1) в степени 2
                { FromBinaryString("111"), 1 }  // x^2+x+1
            };

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            // Assert
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Theory]
        [InlineData("0")]
        [InlineData("1")]
        public void FactorizePolynomial_ForZeroAndOne_ShouldReturnEmpty(string value)
        {
            // Arrange
            BigInteger polynomial = FromBinaryString(value);

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            // Assert
            Assert.Empty(actualFactors);
        }

        [Fact]
        public void FactorizePolynomial_ProductOfTwoIrreduciblesOfSameDegree()
        {
            // Arrange
            // p(x) = (x^3+x+1) * (x^3+x^2+1) = x^6+x^5+x^4+x^3+x^2+x+1
            BigInteger polynomial = FromBinaryString("1111111");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("1011"), 1 },
                { FromBinaryString("1101"), 1 }
            };

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            // Assert
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Fact]
        public void FactorizePolynomial_ForLargeIrreduciblePolynomial()
        {
            // Arrange
            // p(x) = x^16 + x^5 + x^3 + x + 1
            // Это известный неприводимый полином.
            BigInteger largeIrreduciblePolynomial =
                (BigInteger.One << 16) |
                (BigInteger.One << 5) |
                (BigInteger.One << 3) |
                (BigInteger.One << 1) |
                BigInteger.One;

            // Ожидаемый результат - словарь с одним элементом: самим полиномом.
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { largeIrreduciblePolynomial, 1 }
            };

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(largeIrreduciblePolynomial);

            // Assert
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(largeIrreduciblePolynomial));
            Assert.Equal(1, actualFactors[largeIrreduciblePolynomial]);
        }
        
        [Fact]
        public void FactorizePolynomial_ForVeryLargeIrreduciblePolynomial_BeyondLong()
        {
            // Arrange
            // p(x) = x^128 + x^7 + x^2 + x + 1
            // Это стандартный неприводимый полином для поля GF(2^128), используемый в GCM.
            BigInteger largeIrreduciblePolynomial = 
                (BigInteger.One << 128) | 
                (BigInteger.One << 7) | 
                (BigInteger.One << 2) | 
                (BigInteger.One << 1) | 
                BigInteger.One;
            
            // Ожидаемый результат - словарь с одним элементом: самим полиномом.
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { largeIrreduciblePolynomial, 1 }
            };

            // Act
            var actualFactors = GaloisFieldMath.FactorizePolynomial(largeIrreduciblePolynomial);

            // Assert
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(largeIrreduciblePolynomial));
            Assert.Equal(1, actualFactors[largeIrreduciblePolynomial]);
        }
    }
}