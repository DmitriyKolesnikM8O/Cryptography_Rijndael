using System.Collections.Generic;
using System.Numerics;

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
            if (polynomialByte == 0) return false;
            // Полный список неприводимых полиномов степеней 1, 2, 3, 4.
            int[] irreducibleFactors = {
                0b10,      // x
                0b11,      // x+1
                0b101,     // x²+1
                0b111,     // x²+x+1
                0b1001,    // x³+1
                0b1011,    // x³+x+1
                0b1101,    // x³+x²+1
                0b10001,   // x⁴+1
                0b10011,   // x⁴+x+1
                0b10101,   // x⁴+x²+1
                0b10111,   // x⁴+x²+x+1
                0b11001,   // x⁴+x³+1
                0b11011,   // x⁴+x³+x+1
                0b11101,   // x⁴+x³+x²+1
                0b11111    // x⁴+x³+x²+x+1
            };
            
            int p = 0x100 | polynomialByte;

            foreach (var factor in irreducibleFactors)
            {
                if (factor == 0b10) // x
            {
                if ((polynomialByte & 1) == 0) // младший коэффициент = 0 → делится на x
                    return false;
                continue; // иначе — не делится
            }
                if (GetRemainder(p, factor) == 0)
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
            if (divisor == 0) return dividend;

            // Обрезаем до 9 бит (x^8 + ... + 1)
            dividend &= 0x1FF;

            int divisorDeg = BitOperations.Log2((uint)divisor);

            while (true)
            {
                // Обрезаем ПЕРЕД Log2
                int masked = dividend & 0x1FF;
                if (masked == 0) break;

                int dividendDeg = BitOperations.Log2((uint)masked);
                if (dividendDeg < divisorDeg) break;

                int shift = dividendDeg - divisorDeg;
                dividend ^= (divisor << shift);

                // Обрезаем ПОСЛЕ XOR
                dividend &= 0x1FF;
            }

            return dividend & 0xFF; // остаток — младшие 8 бит
        }

        /// <summary>
        /// Определяет степень полинома (позицию старшего установленного бита).
        /// </summary>
        private static int GetPolynomialDegree(int polynomial)
        {
            if (polynomial == 0) return -1;
            for (int i = 15; i >= 0; i--)
            {
                if (((polynomial >> i) & 1) == 1) return i;
            }
            return -1;
        }
    }
}