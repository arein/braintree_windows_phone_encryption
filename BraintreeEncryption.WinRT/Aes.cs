using System;
#if WINRT
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
#else
using System.Security.Cryptography;
#endif
using System.Text;

namespace BraintreeEncryption.Library
{
    public class Aes
    {
#if WINRT
        private readonly SymmetricKeyAlgorithmProvider _aesProvider;
#else
        private readonly AesManaged _aesManaged;
#endif

        public Aes()
        {
#if WINRT
            _aesProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
#else
            _aesManaged = new AesManaged {KeySize = 256, BlockSize = 128};
#endif
        }

        public byte[] GenerateKey()
        {
#if WINRT
            var key = CryptographicBuffer.GenerateRandom(32);
            byte[] b;
            CryptographicBuffer.CopyToByteArray(key, out b);
            return b;
#else
            _aesManaged.GenerateKey();
            return _aesManaged.Key;
#endif
        }

        public byte[] GenerateIV()
        {
#if WINRT
            var iv = CryptographicBuffer.GenerateRandom(16);
            byte[] b;
            CryptographicBuffer.CopyToByteArray(iv, out b);
            return b;
#else
            _aesManaged.GenerateIV();
            return _aesManaged.IV;
#endif
        }

        public string Encrypt(string dataToEncrypt, byte[] aesKey)
        {
            return EncryptWithIv(dataToEncrypt, aesKey, GenerateIV());
        }

        public string EncryptWithIv(string dataToEncrypt, byte[] aesKey, byte[] iv)
        {
#if WINRT
            var key = _aesProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(aesKey));
            var data = CryptographicBuffer.ConvertStringToBinary(dataToEncrypt, BinaryStringEncoding.Utf8);
            var v = CryptographicBuffer.CreateFromByteArray(iv);
            var encryptedBuffer = CryptographicEngine.Encrypt(key, data, v);
            byte[] encryptedBytes;
            CryptographicBuffer.CopyToByteArray(encryptedBuffer, out encryptedBytes);
            var ivWithEncryptedBytes = new byte[iv.Length + encryptedBytes.Length];

            Buffer.BlockCopy(iv, 0, ivWithEncryptedBytes, 0, iv.Length);
            Buffer.BlockCopy(encryptedBytes, 0, ivWithEncryptedBytes, iv.Length, encryptedBytes.Length);

            return Convert.ToBase64String(ivWithEncryptedBytes);
#else
            var dataInBytes = new UTF8Encoding().GetBytes(dataToEncrypt);

            using (var encryptor = _aesManaged.CreateEncryptor(aesKey, iv))
            {
                var encryptedBytes = encryptor.TransformFinalBlock(dataInBytes, 0, dataInBytes.Length);
                var ivWithEncryptedBytes = new byte[iv.Length + encryptedBytes.Length];

                Buffer.BlockCopy(iv, 0, ivWithEncryptedBytes, 0, iv.Length);
                Buffer.BlockCopy(encryptedBytes, 0, ivWithEncryptedBytes, iv.Length, encryptedBytes.Length);

                return Convert.ToBase64String(ivWithEncryptedBytes);
            }
#endif
        }
    }
}
