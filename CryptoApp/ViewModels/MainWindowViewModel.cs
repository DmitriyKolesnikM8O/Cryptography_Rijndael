using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CryptoLib.Algorithms.Rijndael;
using CryptoLib.Algorithms.Rijndael.Enums;
using CryptoLib.Interfaces;
using CryptoLib.Modes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        // --- Свойства, привязанные к UI ---

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(IsNotBusy))]
        private bool _isBusy;

        public bool IsNotBusy => !IsBusy;

        [ObservableProperty]
        private string _sourceFilePath = string.Empty;

        [ObservableProperty]
        private string _targetFilePath = string.Empty;

        [ObservableProperty]
        private string _password = string.Empty;

        [ObservableProperty]
        private double _progress;
        
        [ObservableProperty]
        private string _statusText = "Готов к работе.";

        // Свойства для ComboBox'ов
        public List<CryptoLib.Modes.CipherMode> CipherModes { get; } = Enum.GetValues<CryptoLib.Modes.CipherMode>().ToList();
        public List<CryptoLib.Modes.PaddingMode> PaddingModes { get; } = Enum.GetValues<CryptoLib.Modes.PaddingMode>().ToList();

        [ObservableProperty]
        private CryptoLib.Modes.CipherMode _selectedCipherMode;

        [ObservableProperty]
        private CryptoLib.Modes.PaddingMode _selectedPaddingMode;

        // --- Команды для кнопок ---

        [RelayCommand]
        private async Task SelectSourceFile()
        {
            var dialog = new OpenFileDialog();
            var result = await dialog.ShowAsync(new Window()); // Упрощенный вызов для Avalonia
            if (result != null && result.Length > 0)
            {
                SourceFilePath = result[0];
            }
        }

        [RelayCommand]
        private async Task SelectTargetFile()
        {
            var dialog = new SaveFileDialog();
            var result = await dialog.ShowAsync(new Window());
            if (!string.IsNullOrEmpty(result))
            {
                TargetFilePath = result;
            }
        }

        [RelayCommand]
        private async Task Encrypt()
        {
            await RunCryptoOperation(isEncrypting: true);
        }

        [RelayCommand]
        private async Task Decrypt()
        {
            await RunCryptoOperation(isEncrypting: false);
        }

        // --- Основная логика ---

        private async Task RunCryptoOperation(bool isEncrypting)
        {
            if (IsBusy) return;
            if (string.IsNullOrEmpty(SourceFilePath) || string.IsNullOrEmpty(TargetFilePath) || string.IsNullOrEmpty(Password))
            {
                StatusText = "Ошибка: Укажите исходный файл, файл для результата и пароль.";
                return;
            }

            IsBusy = true;
            StatusText = isEncrypting ? "Шифрование..." : "Дешифрование...";
            Progress = 0;

            try
            {
                // Используем стандартный PBKDF2 для получения ключа и IV из пароля.
                // Это гораздо надежнее, чем просто использовать байты пароля.
                // Для простоты, соль (salt) здесь захардкожена. В реальном приложении ее нужно генерировать и сохранять.
                var salt = Encoding.UTF8.GetBytes("somesalt123");
                using var rfc2898 = new Rfc2898DeriveBytes(Password, salt, 10000, HashAlgorithmName.SHA256);
                
                var key = rfc2898.GetBytes(32); // 256-битный ключ
                var iv = rfc2898.GetBytes(16);  // 128-битный IV
                
                ISymmetricCipher rijndael = new RijndaelCipher(KeySize.K256, BlockSize.B128);
                var context = new CipherContext(rijndael, key, SelectedCipherMode, SelectedPaddingMode, iv);

                if (isEncrypting)
                {
                    await context.EncryptAsync(SourceFilePath, TargetFilePath);
                    StatusText = "Шифрование успешно завершено!";
                }
                else
                {
                    await context.DecryptAsync(SourceFilePath, TargetFilePath);
                    StatusText = "Дешифрование успешно завершено!";
                }
                Progress = 100;
            }
            catch (Exception ex)
            {
                StatusText = $"Ошибка: {ex.Message}";
                Progress = 0;
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}