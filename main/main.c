#include "esp_log.h"
#include "mbedtls/aes.h"
#include <stdio.h>
#include <string.h>

void encrypt_string(const char *input, uint8_t *key, uint8_t *iv) {
  unsigned char output[16]; // char array store output
  mbedtls_aes_context aes;  // aes is simple variable of given type
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256); // set key for encryption
  // this is cryption function which encrypt data
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, strlen(input), iv,
                        (unsigned char *)input, output);
  // print output hex buffer on console
  ESP_LOG_BUFFER_HEX("cbc_encrypt", output, strlen(input));
}

void encrypt_any_length_string(const char *input, uint8_t *key, uint8_t *iv) {
  int padded_input_len = 0;
  int input_len = strlen(input) + 1;
  int module16 = input_len % 16;

  if (input_len < 16)
    padded_input_len = 16;
  else
    padded_input_len = (strlen(input) / 16 + 1) * 16;

  char *padded_input = (char *)malloc(padded_input_len);
  if (!padded_input) {
    printf("Failed to allocate memory\n");
    return;
  }
  memcpy(padded_input, input, strlen(input));
  uint8_t pkc5_value = (17 - module16);
  for (int i = strlen(input); i < padded_input_len; i++) {
    padded_input[i] = pkc5_value;
  }

  unsigned char *encrypt_output = (unsigned char *)malloc(padded_input_len);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_input_len, iv,
                        (unsigned char *)padded_input, encrypt_output);

  ESP_LOG_BUFFER_HEX("cbc_encrypt", encrypt_output, padded_input_len);
}

void app_main() {
  char enc_key[32] = "12345678901234567890123456789012";
  char enc_iv[16] = "1234567890123456";
  char *enc_input = "EncryptionString";

  encrypt_any_length_string(enc_input, (uint8_t *)enc_key, (uint8_t *)enc_iv);
}