using Xunit;
using CryptoLib.Algorithms.Rijndael.GaloisField;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Reflection;

namespace CryptoTests
{
    /// <summary>
    /// Тесты для функционала разложения полиномов произвольной степени на множители.
    /// </summary>
    public class PolynomialFactorizationTests
    {
        // Для доступа к приватным методам через рефлексию
        private static MethodInfo GetPrivateStaticMethod(string methodName, Type[] types)
        {
            var method = typeof(GaloisFieldMath).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static, types);
            if (method == null)
                throw new InvalidOperationException($"Не удалось найти приватный метод {methodName}");
            return method;
        }

        [Theory]
        [InlineData(0b1011, 3)]      // x^3 + x + 1
        [InlineData(0b1, 0)]
        [InlineData(0, -1)]
        [InlineData(0b100000000, 8)] // x^8
        public void GetPolynomialDegreeBig_ShouldReturnCorrectDegree(long poly, int expectedDegree)
        {
            var method = GetPrivateStaticMethod("GetPolynomialDegreeBig", new[] { typeof(long) });
            var result = (int)method.Invoke(null, new object[] { poly });
            Assert.Equal(expectedDegree, result);
        }

        [Theory]
        [InlineData(0b1101101, 0b101, 0b11100, 0b1)]  // (x^6+x^5+x^3+x^2+1)/(x^2+1) = x^4+x^3+x^2, rem 1
        [InlineData(0b1001, 0b11, 0b111, 0)]          // (x^3+1)/(x+1) = x^2+x+1, rem 0
        public void PolynomialDivision_ShouldReturnCorrectQuotientAndRemainder(long dividend, long divisor, long expectedQuotient, long expectedRemainder)
        {
            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(long), typeof(long) });
            var result = ((long, long))method.Invoke(null, new object[] { dividend, divisor });
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Theory]
        [InlineData(0b1111, 0b1001, 0b11)] // НОД(x^3+x^2+x+1, x^3+1) = x+1
        [InlineData(0b10011, 0b101, 0b1)]  // Неприводимый и другой полином
        public void PolynomialGcd_ShouldReturnCorrectGcd(long a, long b, long expectedGcd)
        {
            var method = GetPrivateStaticMethod("PolynomialGcd", new[] { typeof(long), typeof(long) });
            var result = (long)method.Invoke(null, new object[] { a, b });
            Assert.Equal(expectedGcd, result);
        }

        [Theory]
        [InlineData(0b10011, true)]    // x^4+x+1 (неприводимый)
        [InlineData(0b111, true)]      // x^2+x+1 (неприводимый)
        [InlineData(0b10001, false)]   // x^4+1 = (x+1)^4 (приводимый)
        [InlineData(0b110011, false)]  // x^5+x^4+x+1 = (x+1)^2 * (x^3+x^2+1) (приводимый)
        public void IsIrreducibleBig_ShouldWorkCorrectly(long poly, bool expected)
        {
            var method = GetPrivateStaticMethod("IsIrreducibleBig", new[] { typeof(long) });
            var result = (bool)method.Invoke(null, new object[] { poly });
            Assert.Equal(expected, result);
        }

        [Fact]
        public void FactorizePolynomial_ShouldFactorizeCorrectly()
        {
            long polynomial = 0b10000001; // x^7 + 1
            var expectedFactors = new Dictionary<long, int> { { 0b11, 1 }, { 0b1011, 1 }, { 0b1101, 1 } };

            Console.WriteLine($"\n--- DEBUG TRACE: FactorizePolynomial({Convert.ToString(polynomial, 2)}) ---");

            var actualFactors = new Dictionary<long, int>();

            // --- Локальные копии методов из CryptoLib с максимальным логгированием ---

            // Получаем доступ к нужным приватным методам один раз через рефлексию
            var isIrreducibleBigMethod = GetPrivateStaticMethod("IsIrreducibleBig", new[] { typeof(long) });
            var polynomialDivisionMethod = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(long), typeof(long) });
            var findDivisorMethod = GetPrivateStaticMethod("FindDivisor", new[] { typeof(long) });

            void traceAddFactor(Dictionary<long, int> factors, long factor)
            {
                factors.TryGetValue(factor, out int count);
                factors[factor] = count + 1;
                Console.WriteLine($"      -> AddFactor({Convert.ToString(factor, 2)}). New count: {factors[factor]}");
            }

            // Локальная рекурсивная функция с отступом для наглядности
            void traceFactorizeRecursive(long poly, string indent = "")
            {
                Console.WriteLine($"{indent}FactorizeRecursive({Convert.ToString(poly, 2)})");

                if (poly == 1)
                {
                    Console.WriteLine($"{indent}  -> poly is 1, return.");
                    return;
                }

                // Вызываем реальный IsIrreducibleBig
                bool isIrreducible = (bool)isIrreducibleBigMethod.Invoke(null, new object[] { poly });
                if (isIrreducible)
                {
                    Console.WriteLine($"{indent}  -> IsIrreducibleBig returned TRUE. Found a prime factor.");
                    traceAddFactor(actualFactors, poly);
                    return;
                }

                Console.WriteLine($"{indent}  -> IsIrreducibleBig returned FALSE. Poly is reducible. Finding divisor...");
                // Вызываем реальный FindDivisor
                long divisor = (long)findDivisorMethod.Invoke(null, new object[] { poly });
                Console.WriteLine($"{indent}  -> FindDivisor returned: {Convert.ToString(divisor, 2)}");

                // Вызываем реальный PolynomialDivision
                var (quotient, remainder) = ((long, long))polynomialDivisionMethod.Invoke(null, new object[] { poly, divisor });
                Console.WriteLine($"{indent}  -> Quotient is: {Convert.ToString(quotient, 2)} (Remainder: {remainder})");

                Console.WriteLine($"{indent}  -> Recursing into divisor...");
                traceFactorizeRecursive(divisor, indent + "    ");

                Console.WriteLine($"{indent}  -> Recursing into quotient...");
                traceFactorizeRecursive(quotient, indent + "    ");
            }

            // --- ЗАПУСК ТРАССИРОВКИ ---
            // Сначала обрабатываем множитель 'x' (если есть)
            long currentPoly = polynomial;
            while ((currentPoly & 1) == 0)
            {
                traceAddFactor(actualFactors, 0b10);
                currentPoly >>= 1;
            }
            // Запускаем рекурсию для оставшейся части
            traceFactorizeRecursive(currentPoly);


            // --- Вывод финального результата для анализа ---
            Console.WriteLine("\n--- ИТОГОВЫЙ РЕЗУЛЬТАТ РАЗЛОЖЕНИЯ ---");
            if (actualFactors.Count == 0) Console.WriteLine("Множителей не найдено.");
            foreach (var factor in actualFactors)
            {
                Console.WriteLine($"Множитель: {Convert.ToString(factor.Key, 2)} (Степень: {factor.Value})");
            }
            Console.WriteLine("--- КОНЕЦ РЕЗУЛЬТАТА ---\n");



            // --- Assert-ы для проверки ---
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
            // Пример: x^4 + 1 = (x+1)^4
            // Полином: 0b10001
            long polynomial = 0b10001;

            var expectedFactors = new Dictionary<long, int>
            {
                { 0b11, 4 } // (x+1) со степенью 4
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(0b11));
            Assert.Equal(4, actualFactors[0b11]);
        }

        [Fact]
        public void FactorizePolynomial_WithXAsFactor()
        {
            // Пример: x^4 + x = x * (x^3+1) = x * (x+1) * (x^2+x+1)
            // Полином: 0b10010
            long polynomial = 0b10010;

            var expectedFactors = new Dictionary<long, int>
            {
                { 0b10, 1 },   // x
                { 0b11, 1 },   // x+1
                { 0b111, 1 }   // x^2+x+1
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
        public void DEBUG_STEP_1_PolynomialDivision()
        {
            Console.WriteLine("\n--- ОТЛАДКА: PolynomialDivision ---");
            long dividend = 0b1000001; // x^6+1, как в логе
            long divisor = 0b11;      // x+1

            Console.WriteLine($"Делим {Convert.ToString(dividend, 2)} на {Convert.ToString(divisor, 2)}");

            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(long), typeof(long) });
            var result = ((long, long))method.Invoke(null, new object[] { dividend, divisor });
            
            Console.WriteLine($"Ожидаемое частное (ручной расчет): 1111111 (x^6+...+1)");
            Console.WriteLine($"Фактическое частное (из лога):     111111 (x^5+...+1)");
            Console.WriteLine($"РЕАЛЬНОЕ частное (из кода):       {Convert.ToString(result.Item1, 2)}");
            Console.WriteLine($"РЕАЛЬНЫЙ остаток (из кода):        {result.Item2}");

            // Тест провалится, если частное неверное, и мы это увидим
            Assert.Equal(0b111111, result.Item1);
        }

        [Fact]
        public void DEBUG_STEP_2_IsIrreducibleBig()
        {
            Console.WriteLine("\n--- ОТЛАДКА: IsIrreducibleBig ---");
            long polynomial = 0b1111111; // Частное из правильного деления x^7+1 на x+1
            
            Console.WriteLine($"Проверяем на неприводимость: {Convert.ToString(polynomial, 2)} (x^6+x^5+...+1)");
            Console.WriteLine("Ожидание: FALSE (т.к. он равен (x^3+x+1)(x^3+x^2+1))");

            // Получаем доступ к приватным методам, которые использует IsIrreducibleBig
            var modPowerMethod = GetPrivateStaticMethod("PolynomialModPower", new[] { typeof(long), typeof(int), typeof(long) });
            var gcdMethod = GetPrivateStaticMethod("PolynomialGcd", new[] { typeof(long), typeof(long) });

            // --- Локальная копия IsIrreducibleBig с логгированием ---
            bool traceIsIrreducibleBig(long poly)
            {
                int degree = (int)GetPrivateStaticMethod("GetPolynomialDegreeBig", new[] { typeof(long) }).Invoke(null, new object[] { poly });
                long h = 0b10; // h(x) = x

                for (int i = 1; i <= degree / 2; i++)
                {
                    h = (long)modPowerMethod.Invoke(null, new object[] { h, 2, poly });
                    long gcd = (long)gcdMethod.Invoke(null, new object[] { poly, h ^ 0b10 });
                    
                    Console.WriteLine($"  i={i}: h=x^(2^{i}) mod p(x) = {Convert.ToString(h, 2)},  НОД(p, h-x) = {Convert.ToString(gcd, 2)}");
                    
                    if (gcd != 1)
                    {
                        Console.WriteLine("  --> НОД не равен 1. Полином ПРИВОДИМЫЙ.");
                        return false;
                    }
                }
                Console.WriteLine("  --> Все НОД равны 1. Полином НЕПРИВОДИМЫЙ.");
                return true;
            }

            bool actual = traceIsIrreducibleBig(polynomial);
            Assert.False(actual);
        }
    }
}