```
Cryptography_Rijndael/
│
├── Cryptography_Rijndael.sln              # Файл всего решения
│
├── CryptoLib/                             # Основная библиотека классов (Ядро)
│   │
│   ├── Interfaces/                        # КОД ИЗ ЛР №1
│   │   └── ISymmetricCipher.cs            #   Ключевой интерфейс, который должен реализовать наш Rijndael
│   │
│   ├── Modes/                             # КОД ИЗ ЛР №1
│   │   │
│   │   ├── CipherContext.cs               #   Главный класс для управления шифрованием
│   │   │
│   │   ├── Enums/                         #   Перечисления для режимов и набивок
│   │   │   ├── CipherModeType.cs
│   │   │   └── PaddingModeType.cs
│   │   │
│   │   └── Implementations/               #   Готовые реализации режимов и набивок
│   │       ├── Modes/                     #     - ECB, CBC, CTR и т.д.
│   │       └── Paddings/                  #     - PKCS7, Zeros и т.д.
│   │
│   └── Algorithms/                        # Реализация специфичных алгоритмов
│       │
│       └── Rijndael/                      # Всё, что относится к этой лабораторной работе
│           │
│           ├── Enums/                      
│           │   ├── BlockSize.cs
│           │   └── KeySize.cs
│           │
│           ├── GaloisField/               # (Задание 1) Реализация математики поля Галуа
│           │   └── GaloisFieldMath.cs
│           │
│           ├── RijndaelCipher.cs          # (Задание 2) Основной класс, реализующий ISymmetricCipher
│           ├── RijndaelKeyScheduler.cs    # (Задание 2) Логика расширения ключа для Rijndael
│           └── SBox.cs                    # (Задание 2) Логика генерации S-матриц
│
├── CryptoApp/                             # GUI-приложение на Avalonia
│   │
│   ├── Views/                             # Представления (AXAML-разметка)
│   │   └── MainWindow.axaml
│   │
│   ├── ViewModels/                        # Модели представлений (логика и состояние UI)
│   │   ├── ViewModelBase.cs
│   │   └── MainViewModel.cs
│   │
│   ├── Services/                          # Вспомогательные сервисы для UI
│   │   └── FileDialogService.cs
│   │
│   ├── App.axaml                          # Файл определения приложения
│   ├── Program.cs                         # Точка входа приложения
│   └── CryptoApp.csproj                   # Файл проекта, зависит от CryptoLib
│
├── CryptoDemo/                            # Консольное приложение для демонстрации
│   │
│   ├── Demos/                             # Классы для демонстрации отдельных заданий
│   │   ├── Task1_GaloisFieldDemo.cs
│   │   └── Task2_3_RijndaelDemo.cs
│   │
│   ├── Program.cs                         # Точка входа, меню
│   └── CryptoDemo.csproj                  # Файл проекта, зависит от CryptoLib
│
└── CryptoTests/                           # Модульные тесты
    │
    ├── Rijndael/                          # Тесты для новой реализации
    │   ├── GaloisFieldMathTests.cs
    │   └── RijndaelCipherTests.cs         # Тесты против официальных векторов FIPS-197 (AES)
    │
    └── CryptoTests.csproj                 # Файл проекта, зависит от CryptoLib
```


TO-DO:
- AdvancedTests как в DES
- нужно добавить документацию
- нужно переделать архитектуру
- приложение