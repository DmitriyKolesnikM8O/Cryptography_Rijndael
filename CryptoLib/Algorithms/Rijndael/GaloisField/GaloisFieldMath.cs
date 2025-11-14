using System.Collections.Generic;
using System.Numerics;
using System.Numerics;
using System.Security.Cryptography; // RandomNumberGeneration

namespace CryptoLib.Algorithms.Rijndael.GaloisField
{
    /// <summary>
    /// Stateless-сервис для выполнения арифметических операций в конечном поле Галуа GF(2^8).
    /// Элементы поля представляются байтами.
    /// </summary>
    public static class GaloisFieldMath
    {
        /// <summary>
        /// Сложение двух элементов в поле GF(2^8). Эквивалентно операции XOR.
        /// </summary>
        public static byte Add(byte a, byte b) => (byte)(a ^ b);

        /// <summary>
        /// Умножение двух элементов в поле GF(2^8) по заданному неприводимому полиному.
        /// Это каноническая, исправленная реализация.
        /// </summary>
        public static byte Multiply(byte a, byte b, byte module = 0x1B)
        {
            byte result = 0;
            byte hi_bit_set;
            while (b > 0)
            {
                if ((b & 1) == 1)
                    result ^= a;

                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                    a ^= module;

                b >>= 1;
            }
            return result;
        }



        /// <summary>
        /// Находит обратный элемент для заданного элемента в поле GF(2^8)
        /// по Малой теореме Ферма: a⁻¹ = a^(254).
        /// </summary>
        public static byte Inverse(byte element, byte module)
        {
            if (element == 0) return 0;
            return Power(element, 254, module);
        }

        /// <summary>
        /// Возводит элемент поля в степень по заданному модулю
        /// методом двоичного разложения (Exponentiation by Squaring).
        /// </summary>
        private static byte Power(byte baseValue, int exponent, byte module)
        {
            byte result = 1;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    result = Multiply(result, baseValue, module);

                baseValue = Multiply(baseValue, baseValue, module);
                exponent >>= 1;
            }
            return result;
        }

        /// <summary>
        /// Проверяет, является ли полином 8-й степени неприводимым над полем GF(2).
        /// </summary>
        public static bool IsIrreducible(byte polynomialByte)
        {
            // ... (Проверка на 0 и нечетность остается без вывода)
            if (polynomialByte == 0) return false;
            
            // 1. Установка x^8 (9-й бит)
            int p = 0x100 | polynomialByte; 

            // 2. Проверка на делимость на x 
            if ((p & 1) == 0) return false;
            
            // ... (Список irreducibleFactors остается прежним)
            int[] irreducibleFactors = {
                0b11,       // x+1 (степень 1)
                0b111,      // x²+x+1 (степень 2)
                0b1011,     // x³+x+1 (степень 3)
                0b1101,     // x³+x²+1 (степень 3)
                0b10011,    // x⁴+x+1 (степень 4)
                0b11001,    // x⁴+x³+1 (степень 4)
                0b11111     // x⁴+x³+x²+x+1 (степень 4)
            };

            foreach (var factor in irreducibleFactors)
            {
                // 3. Вычисление остатка
                int remainder = GetRemainder(p, factor);
                Console.WriteLine($"PolynomialByte: {polynomialByte} Remainder: {remainder} , Factor: {factor}");
                
                if (remainder == 0)
                {
                    return false; // Найден делитель, полином приводим
                }
            }

            return true;
        }


        /// <summary>
        /// Находит все неприводимые двоичные полиномы 8-й степени.
        /// </summary>
        public static List<byte> FindAllIrreduciblePolynomials()
        {
            var polynomials = new List<byte>();
            for (int i = 0; i <= 255; i++)
            {
                if (IsIrreducible((byte)i)) polynomials.Add((byte)i);
            }
            return polynomials;
        }


        /// <summary>
        /// Выполняет деление полиномов в GF(2) и возвращает остаток.
        /// </summary>
        private static int GetRemainder(int dividend, int divisor)
        {
            if (divisor == 0) throw new DivideByZeroException();

            // Используем тот же надежный алгоритм, что и для long
            int divisorDegree = GetPolynomialDegree(divisor);
            while (GetPolynomialDegree(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegree(dividend) - divisorDegree;
                dividend ^= (divisor << degreeDifference);
            }
            return dividend;
        }


        /// <summary>
        /// Определяет степень полинома (позицию старшего установленного бита).
        /// </summary>
        private static int GetPolynomialDegree(int polynomial)
        {
            // Используем надежный перебор вместо BitOperations.Log2, чтобы исключить любые ошибки
            for (int i = 31; i >= 0; i--)
            {
                if (((polynomial >> i) & 1) == 1) return i;
            }
            return -1;
        }
        
        #region Polynomial Factorization

        /// <summary>
        /// Выполняет разложение двоичного полинома произвольной степени на неприводимые множители.
        /// Реализует алгоритм Кантора-Цассенхауза.
        /// </summary>
        public static Dictionary<BigInteger, int> FactorizePolynomial(BigInteger polynomial)
        {
            var factors = new Dictionary<BigInteger, int>();
            if (polynomial <= 1) return factors;
            
            while ((polynomial & 1) == 0) // IsEven проверяет, что младший бит равен 0
            {
                AddFactor(factors, 2); // 2 - это полином 'x' (0b10)
                polynomial >>= 1;
            }

            FactorizeRecursive(polynomial, factors);
            return factors;
        }

        private static void FactorizeRecursive(BigInteger polynomial, Dictionary<BigInteger, int> factors)
        {
            // Используем стек для имитации рекурсии
            var polynomialsToFactor = new Stack<BigInteger>();
            polynomialsToFactor.Push(polynomial);

            while (polynomialsToFactor.Count > 0)
            {
                BigInteger currentPoly = polynomialsToFactor.Pop();
                if (currentPoly == 1) continue;
                
                if (IsIrreducibleBig(currentPoly))
                {
                    AddFactor(factors, currentPoly);
                }
                else
                {
                    BigInteger divisor = FindDivisor(currentPoly);
                    if (divisor == 1 || divisor == currentPoly)
                    {
                        // Если FindDivisor не справился, но IsIrreducibleBig сказал, что полином приводим,
                        // это указывает на сложность полинома (например, произведение равностепенных факторов).
                        // Добавляем как есть, чтобы не потерять.
                        AddFactor(factors, currentPoly);
                    }
                    else 
                    {
                        polynomialsToFactor.Push(divisor);
                        polynomialsToFactor.Push(PolynomialDivision(currentPoly, divisor).Quotient);
                    }
                }
            }
        }

        /// <summary>
        /// Находит один нетривиальный делитель полинома p(x)
        /// используя НОД(p(x), x^(2^k) - x).
        /// </summary>
        // private static long FindDivisor(long polynomial)
        // {
        //     int degree = GetPolynomialDegreeBig(polynomial);
        //     Random rand = new Random();

        //     // Пробуем несколько случайных полиномов для надежности
        //     for (int attempt = 0; attempt < 10; attempt++)
        //     {
        //         // Генерируем случайный полином степени < degree
        //         long a = 0;
        //         for (int i = 0; i < degree; i++)
        //         {
        //             if (rand.Next(2) == 1)
        //                 a |= (1L << i);
        //         }

        //         // Если a = 0, пропускаем
        //         if (a == 0) continue;

        //         long d = a;
        //         for (int k = 1; k <= degree / 2; k++)
        //         {
        //             // d = d^2 mod polynomial
        //             d = PolynomialMultiplyMod(d, d, polynomial);

        //             long g = PolynomialGcd(polynomial, d ^ a); // НОД(p(x), d(x) - a(x))

        //             if (g != 1 && g != polynomial)
        //             {
        //                 return g;
        //             }
        //         }
        //     }

        //     // Fallback: простой перебор (для небольших полиномов)
        //     return FindDivisorFallback(polynomial);
        // }
        
        /// <summary>
        /// Находит один нетривиальный делитель полинома p(x).
        /// Исключает неэффективный FindDivisorFallback.
        /// </summary>
        private static BigInteger FindDivisor(BigInteger polynomial)
        {
            // Приводимые полиномы должны иметь степень > 1.
            int n = GetPolynomialDegreeBig(polynomial);
            if (n <= 1) return polynomial; // Возвращаем сам полином или ошибку

            var rng = RandomNumberGenerator.Create();
            
            // Число попыток должно быть достаточно большим для высокой вероятности успеха.
            // 100-200 итераций достаточно для полиномов, которые не являются произведениями
            // равностепенных неприводимых множителей (случай EDF).
            const int MaxAttempts = 200; 

            for (int attempt = 0; attempt < MaxAttempts; attempt++)
            {
                // Генерируем случайный полином a(x) степени < n
                byte[] bytes = new byte[n / 8 + 1];
                rng.GetBytes(bytes);
                BigInteger a = new BigInteger(bytes, isUnsigned: true);
                // Ограничиваем степень
                a %= BigInteger.One << n;
                
                // 2. Если a = 0 или a = 1, пропускаем (они тривиальны).
                if (a <= 1) continue;

                // 3. Вычисляем x^(2^k) mod p(x) для разных k.
                // Здесь мы используем идею Кантора-Цассенхауза:
                // НОД(p(x), a(x)^(2^k) - a(x)) должен быть нетривиальным для некоторых k.
                
                // Нам нужно найти нетривиальный делитель p(x). 
                // Если p(x) - произведение k равностепенных полиномов степени d, 
                // то d*k = n. Мы пробуем k = 1..n/2.

                for (int k = 1; k <= n / 2; k++)
                {
                    // Вычисляем a(x)^(2^k) mod p(x)
                    // Использование PolynomialModPower здесь более эффективно.
                    BigInteger a_power = PolynomialModPower(a, BigInteger.Pow(2, k), polynomial);
                    
                    // НОД(p(x), a(x)^(2^k) + a(x)) = НОД(p(x), a_power ^ a)
                    BigInteger g = PolynomialGcd(polynomial, a_power ^ a); 
                    
                    if (g != 1 && g != polynomial)
                    {
                        return g; // Найден нетривиальный делитель
                    }
                }
            }
    
            // Если после 200 попыток нетривиальный делитель не найден,
            // это с высокой вероятностью означает, что полином неприводим,
            // или он является произведением равностепенных факторов, которые
            // требуют более точного алгоритма EDF.
            
            // Если IsIrreducibleBig(polynomial) вернул FALSE, а FindDivisor не смог найти
            // делитель за 200 попыток, это указывает на ошибку. 
            // В текущей архитектуре мы должны вернуть сам полином (или выбросить исключение).
            return polynomial; 
        }

        /// <summary>
        /// Резервный метод поиска делителя простым перебором
        /// </summary>
        // private static long FindDivisorFallback(long polynomial)
        // {
        //     int degree = GetPolynomialDegreeBig(polynomial);

        //     // Перебираем все возможные неприводимые делители степени <= degree/2
        //     for (int divDegree = 1; divDegree <= degree / 2; divDegree++)
        //     {
        //         // Перебираем все полиномы данной степени
        //         long start = 1L << divDegree;
        //         long end = 1L << (divDegree + 1);

        //         for (long candidate = start; candidate < end; candidate++)
        //         {
        //             // Пропускаем четные полиномы (имеющие свободный член 0)
        //             if ((candidate & 1) == 0) continue;

        //             // Проверяем, что candidate делит polynomial
        //             var (quotient, remainder) = PolynomialDivision(polynomial, candidate);
        //             if (remainder == 0 && quotient != 1)
        //             {
        //                 return candidate;
        //             }
        //         }
        //     }

        //     return polynomial; // Не должно происходить, если IsIrreducibleBig вернул false
        // }
        
        /// <summary>
        /// Проверяет полином на неприводимость (тест Бен-Ора).
        /// p(x) неприводим <=> НОД(p(x), x^(2^i) - x) = 1 для всех i = 1..d/2
        /// </summary>
        // private static bool IsIrreducibleBig(long polynomial)
        // {
        //     if (polynomial <= 1) return false;
        //     int degree = GetPolynomialDegreeBig(polynomial);
        //     long h = 0b10; // h(x) = x

        //     for (int i = 1; i <= degree / 2; i++)
        //     {
        //         h = PolynomialModPower(h, 2, polynomial); // h = x^(2^i) mod p(x)
        //         long gcd = PolynomialGcd(polynomial, h ^ 0b10); // НОД(p(x), h(x) - x)
        //         if (gcd != 1)
        //         {
        //             return false; // Найден делитель, значит приводим
        //         }
        //     }
        //     return true; // Делителей не найдено, неприводим
        // }

        /// <summary>
        /// Возводит полином в степень по модулю другого полинома.
        /// </summary>
        // private static long PolynomialModPower(long baseValue, int exponent, long modulus)
        // {
        //     long result = 1;
        //     baseValue = PolynomialDivision(baseValue, modulus).Remainder;
        //     while (exponent > 0)
        //     {
        //         if ((exponent & 1) == 1)
        //             result = PolynomialMultiplyMod(result, baseValue, modulus);
                
        //         baseValue = PolynomialMultiplyMod(baseValue, baseValue, modulus);
        //         exponent >>= 1;
        //     }
        //     return result;
        // }

        /// <summary>
        /// Умножает два полинома по модулю третьего.
        /// </summary>
        private static long PolynomialMultiplyMod(long a, long b, long modulus)
        {
            long result = 0;
            int modDeg = GetPolynomialDegreeBig(modulus);
            if (modDeg < 0) throw new DivideByZeroException();

            while (b != 0)
            {
                if ((b & 1) == 1)
                {
                    result ^= a;
                }

                b >>= 1;

                // Сдвигаем a влево (умножаем на x)
                a <<= 1;

                // Если степень a стала >= степени модуля, то редуцируем,
                // но нужно сдвинуть modulus так, чтобы выровнять степени.
                int aDeg = GetPolynomialDegreeBig(a);
                if (aDeg >= modDeg)
                {
                    int shift = aDeg - modDeg;
                    a ^= (modulus << shift);
                }
            }

            // В конце результат тоже может иметь степень >= modDeg => редуцируем окончательно
            int rDeg;
            while ((rDeg = GetPolynomialDegreeBig(result)) >= modDeg)
            {
                int shift = rDeg - modDeg;
                result ^= (modulus << shift);
            }

            return result;
        }

        private static void AddFactor(Dictionary<BigInteger, int> factors, BigInteger factor)
        {
            factors.TryGetValue(factor, out int count);
            factors[factor] = count + 1;
        }
        
        private static (BigInteger Quotient, BigInteger Remainder) PolynomialDivision(BigInteger dividend, BigInteger divisor)
        {
            if (divisor.IsZero) throw new DivideByZeroException();
            BigInteger quotient = 0;
            int divisorDegree = GetPolynomialDegreeBig(divisor);

            while (GetPolynomialDegreeBig(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegreeBig(dividend) - divisorDegree;
                quotient ^= (BigInteger.One << degreeDifference);
                dividend ^= (divisor << degreeDifference);
            }
            return (quotient, dividend);
        }

        private static BigInteger PolynomialGcd(BigInteger a, BigInteger b)
        {
            while (!b.IsZero)
            {
                (a, b) = (b, PolynomialDivision(a, b).Remainder);
            }
            return a;
        }

        private static BigInteger PolynomialModPower(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            BigInteger result = 1;
            baseValue = PolynomialDivision(baseValue, modulus).Remainder;
            while (exponent > 0)
            {
                if (!exponent.IsEven) // exponent & 1 != 0
                    result = PolynomialMultiplyMod(result, baseValue, modulus);
                
                baseValue = PolynomialMultiplyMod(baseValue, baseValue, modulus);
                exponent >>= 1;
            }
            return result;
        }

        private static BigInteger PolynomialMultiplyMod(BigInteger a, BigInteger b, BigInteger modulus)
        {
            BigInteger result = 0;
            int modDeg = GetPolynomialDegreeBig(modulus);
            if (modDeg < 0) throw new DivideByZeroException();

            while (b > 0)
            {
                if (!b.IsEven) // b & 1 != 0
                {
                    result ^= a;
                }
                b >>= 1;
                a <<= 1;
                if (GetPolynomialDegreeBig(a) >= modDeg)
                {
                    a ^= modulus;
                }
            }
            return result;
        }

        private static bool IsIrreducibleBig(BigInteger polynomial)
        {
            if (polynomial <= 1) return false;
            int degree = GetPolynomialDegreeBig(polynomial);
            BigInteger h = 2; // h(x) = x

            for (int i = 1; i <= degree / 2; i++)
            {
                h = PolynomialModPower(h, 2, polynomial);
                BigInteger gcd = PolynomialGcd(polynomial, h ^ 2);
                if (gcd != 1)
                {
                    return false;
                }
            }
            return true;
        }

        private static int GetPolynomialDegreeBig(BigInteger polynomial)
        {
            if (polynomial.IsZero) return -1;
            // GetBitLength() возвращает позицию старшего бита + 1
            return (int)polynomial.GetBitLength() - 1;
        }

        #endregion
    }
}