namespace CryptoLib.Algorithms.Rijndael.GaloisField
{
    /// <summary>
    /// Stateless-сервис для выполнения арифметических операций в конечном поле Галуа GF(2^8).
    /// Элементы поля представляются байтами.
    /// </summary>
    public static class GaloisFieldMath
    {
        /// <summary>
        /// Сложение двух элементов в поле GF(2^8).
        /// Эквивалентно операции XOR.
        /// </summary>
        /// <param name="a">Первый операнд (байт).</param>
        /// <param name="b">Второй операнд (байт).</param>
        /// <returns>Результат сложения (байт).</returns>
        public static byte Add(byte a, byte b)
        {
            return (byte)(a ^ b);
        }

        /// <summary>
        /// Умножение двух элементов в поле GF(2^8) по заданному неприводимому полиному.
        /// Реализует алгоритм "Russian Peasant Multiplication".
        /// </summary>
        /// <param name="a">Первый множитель (байт).</param>
        /// <param name="b">Второй множитель (байт).</param>
        /// <param name="module">Неприводимый полином 8-й степени, используемый для редукции. 
        /// Например, для AES это 0x11B (x^8 + x^4 + x^3 + x + 1).</param>
        /// <returns>Результат умножения (байт).</returns>
        public static byte Multiply(byte a, byte b, byte module)
        {
            byte p = 0; // product

            for (int i = 0; i < 8; i++)
            {
                // Если младший бит b равен 1, добавляем a к результату
                if ((b & 1) == 1)
                {
                    p = Add(p, a); // p ^= a;
                }

                // Готовим b к следующей итерации
                b >>= 1;

                // Проверяем, произойдет ли "переполнение" при сдвиге a
                bool highBitSet = (a & 0x80) == 0x80; // 0x80 это 1000 0000

                // Умножаем a на x (сдвигаем влево)
                a <<= 1;

                // Если было переполнение, выполняем редукцию по модулю
                if (highBitSet)
                {
                    a = Add(a, module); // a ^= module;
                }
            }

            return p;
        }

        /// <summary>
        /// Находит обратный элемент для заданного элемента в поле GF(2^8).
        /// Обратный элемент a⁻¹ такой, что a * a⁻¹ ≡ 1 (mod module).
        /// Использует Малую теорему Ферма: a⁻¹ = a^(254).
        /// </summary>
        /// <param name="element">Элемент, для которого нужно найти обратный.</param>
        /// <param name="module">Неприводимый полином, определяющий поле.</param>
        /// <returns>Обратный элемент. Обратный для 0 условно равен 0.</returns>
        public static byte Inverse(byte element, byte module)
        {
            // Обратный элемент для 0 не определен, но в криптографии (например, в AES S-Box)
            // его принято отображать в 0 для сохранения биективности.
            if (element == 0)
            {
                return 0;
            }

            // По Малой теореме Ферма для поля GF(2^8), a⁻¹ = a^(256-2) = a^254
            return Power(element, 254, module);
        }

        /// <summary>
        /// Возводит элемент поля в степень по заданному модулю.
        /// Реализует алгоритм возведения в степень методом двоичного разложения (Exponentiation by Squaring).
        /// </summary>
        /// <param name="baseValue">Основание (элемент поля).</param>
        /// <param name="exponent">Показатель степени.</param>
        /// <param name="module">Неприводимый полином, определяющий поле.</param>
        /// <returns>Результат возведения в степень.</returns>
        private static byte Power(byte baseValue, int exponent, byte module)
        {
            byte result = 1;
            byte currentPower = baseValue;

            while (exponent > 0)
            {
                // Если текущий бит степени равен 1
                if ((exponent & 1) == 1)
                {
                    result = Multiply(result, currentPower, module);
                }

                // Переходим к следующему биту степени, возводя основание в квадрат
                currentPower = Multiply(currentPower, currentPower, module);
                exponent >>= 1; // Сдвигаем степень вправо
            }

            return result;
        }
        
        /// <summary>
        /// Проверяет, является ли полином 8-й степени неприводимым над полем GF(2).
        /// Полином представлен младшими 8 битами, старший бит x^8 подразумевается.
        /// </summary>
        /// <remarks>
        /// Полином P(x) степени 8 является неприводимым, если он не делится без остатка
        /// на любой неприводимый полином степени от 1 до 4.
        /// </remarks>
        /// <param name="polynomialByte">Младшие 8 бит полинома 8-й степени.</param>
        /// <returns>True, если полином неприводим, иначе false.</returns>
        public static bool IsIrreducible(byte polynomialByte)
        {
            // Полином 8-й степени - это 9-битное число, где старший бит (x^8) всегда 1.
            short polynomial = (short)(0x100 | polynomialByte);

            // Тестовые неприводимые полиномы степеней от 1 до 4:
            // deg(1): x+1 (0x03)
            // deg(2): x^2+x+1 (0x07)
            // deg(3): x^3+x+1 (0x0B), x^3+x^2+1 (0x0D)
            // deg(4): x^4+x+1 (0x13), x^4+x^3+1 (0x19), x^4+x^3+x^2+x+1 (0x1F)
            short[] testDivisors = { 0x03, 0x07, 0x0B, 0x0D, 0x13, 0x19, 0x1F };

            foreach (var divisor in testDivisors)
            {
                if (GetRemainder(polynomial, divisor) == 0)
                {
                    // Если делится без остатка, значит полином приводимый.
                    return false;
                }
            }
            
            // Если не разделился ни на один из тестовых, значит неприводимый.
            return true;
        }

        /// <summary>
        /// Находит все неприводимые двоичные полиномы 8-й степени.
        /// </summary>
        /// <returns>Список байтов, представляющих неприводимые полиномы.</returns>
        public static List<byte> FindAllIrreduciblePolynomials()
        {
            var irreduciblePolynomials = new List<byte>();
            // Перебираем все возможные полиномы степени 7 и ниже.
            // Вместе с подразумеваемым x^8 они образуют все полиномы 8-й степени.
            for (int i = 0; i <= 255; i++)
            {
                if (IsIrreducible((byte)i))
                {
                    irreduciblePolynomials.Add((byte)i);
                }
            }
            return irreduciblePolynomials;
        }

        #region Private Helpers for Polynomial Division

        /// <summary>
        /// Выполняет деление полиномов в GF(2) и возвращает остаток.
        /// </summary>
        /// <param name="dividend">Делимое (полином).</param>
        /// <param name="divisor">Делитель (полином).</param>
        /// <returns>Остаток от деления.</returns>
        private static short GetRemainder(short dividend, short divisor)
        {
            int divisorDegree = GetPolynomialDegree(divisor);
            while (GetPolynomialDegree(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegree(dividend) - divisorDegree;
                short alignedDivisor = (short)(divisor << degreeDifference);
                dividend = (short)(dividend ^ alignedDivisor);
            }
            return dividend;
        }

        /// <summary>
        /// Определяет степень полинома (позицию старшего установленного бита).
        /// </summary>
        /// <param name="polynomial">Полином.</param>
        /// <returns>Степень полинома.</returns>
        private static int GetPolynomialDegree(short polynomial)
        {
            if (polynomial == 0) return -1;
            
            short temp = polynomial;

            // Можно было бы использовать логарифм, но побитовый сдвиг надежнее и нагляднее.
            for (int i = 15; i >= 0; i--)
            {
                if (((temp >> i) & 1) == 1)
                {
                    return i;
                }
            }
            return -1;
        }

        #endregion
    }
}