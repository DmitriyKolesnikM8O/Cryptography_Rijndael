namespace CryptoLib.Algorithms.Rijndael
{
    /// <summary>
    /// Отвечает за процедуру расширения ключа (Key Schedule) для алгоритма Rijndael.
    /// Генерирует набор раундовых ключей из исходного мастер-ключа.
    /// </summary>
    public class RijndaelKeyScheduler
    {
        private readonly SBox _sBox;

        /// <summary>
        /// Константы раундов (Rcon), используемые в процедуре расширения ключа.
        /// Rcon[i] = [ RC[i], 0x00, 0x00, 0x00 ], где RC[1]=1, RC[i]=2*RC[i-1] в поле GF(2^8)
        /// с модулем 0x11B.
        /// </summary>
        private static readonly byte[] Rcon = {
            0x00, // Rcon[0] не используется
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
        };

        /// <summary>
        /// Инициализирует новый экземпляр Key Scheduler.
        /// </summary>
        /// <param name="sBox">Экземпляр SBox для выполнения операции SubWord.</param>
        public RijndaelKeyScheduler(SBox sBox)
        {
            _sBox = sBox;
        }

        /// <summary>
        /// Выполняет расширение ключа.
        /// </summary>
        /// <param name="key">Мастер-ключ.</param>
        /// <param name="blockSizeBytes">Размер блока в байтах.</param>
        /// <param name="keySizeBytes">Размер ключа в байтах.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Двумерный массив, содержащий раундовые ключи.</returns>
        public byte[][] ExpandKey(byte[] key, int blockSizeBytes, int keySizeBytes, int rounds)
        {
            // Количество 4-байтных слов в ключе (Nk)
            int nk = keySizeBytes / 4;
            // Общее количество байт в расширенном ключе
            int expandedKeySizeBytes = blockSizeBytes * (rounds + 1);

            // Создаем плоский массив для хранения всех байт расширенного ключа
            var expandedKey = new byte[expandedKeySizeBytes];
            // Копируем исходный мастер-ключ в начало
            Array.Copy(key, 0, expandedKey, 0, keySizeBytes);

            // Итерируемся, начиная с конца мастер-ключа, и генерируем оставшиеся байты
            for (int i = keySizeBytes; i < expandedKeySizeBytes; i += 4)
            {
                // Берем предыдущее 4-байтное слово
                var temp = new byte[4];
                Array.Copy(expandedKey, i - 4, temp, 0, 4);

                // Индекс текущего генерируемого слова
                int currentWordIndex = i / 4;

                // Если это начало нового блока ключа, применяем сложную трансформацию
                if (currentWordIndex % nk == 0)
                {
                    temp = RotWord(temp);
                    temp = SubWord(temp);
                    temp[0] ^= Rcon[currentWordIndex / nk];
                }
                // Специальное правило для 256-битных ключей
                else if (nk > 6 && currentWordIndex % nk == 4)
                {
                    temp = SubWord(temp);
                }

                // XOR с W[i-Nk] для получения нового слова W[i]
                for (int j = 0; j < 4; j++)
                {
                    expandedKey[i + j] = (byte)(expandedKey[i - keySizeBytes + j] ^ temp[j]);
                }
            }
            
            // Форматируем плоский массив в двумерный массив раундовых ключей
            return FormatRoundKeys(expandedKey, blockSizeBytes, rounds);
        }

        /// <summary>
        /// Применяет S-Box к каждому байту 4-байтного слова.
        /// </summary>
        private byte[] SubWord(byte[] word)
        {
            return new[]
            {
                _sBox.SBoxTable[word[0]],
                _sBox.SBoxTable[word[1]],
                _sBox.SBoxTable[word[2]],
                _sBox.SBoxTable[word[3]]
            };
        }

        /// <summary>
        /// Выполняет циклический сдвиг байтов в слове влево: [b0,b1,b2,b3] -> [b1,b2,b3,b0].
        /// </summary>
        private byte[] RotWord(byte[] word)
        {
            return new[] { word[1], word[2], word[3], word[0] };
        }

        /// <summary>
        /// Преобразует плоский массив расширенного ключа в массив раундовых ключей.
        /// </summary>
        private byte[][] FormatRoundKeys(byte[] expandedKey, int blockSizeBytes, int rounds)
        {
            var roundKeys = new byte[rounds + 1][];
            for (int i = 0; i < rounds + 1; i++)
            {
                roundKeys[i] = new byte[blockSizeBytes];
                Array.Copy(expandedKey, i * blockSizeBytes, roundKeys[i], 0, blockSizeBytes);
            }
            return roundKeys;
        }
    }
}
