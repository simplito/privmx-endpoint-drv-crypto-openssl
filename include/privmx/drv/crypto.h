#ifndef __PRIVMX_DRIVER_CRYPTO_H__
#define __PRIVMX_DRIVER_CRYPTO_H__

#ifdef __cplusplus
extern "C" {
#endif

int privmxDrvCrypto_version(unsigned int* version); // version: 1
int privmxDrvCrypto_randomBytes(char* buf, unsigned int len);
int privmxDrvCrypto_md(const char* data, int datalen, const char* config, char** out, unsigned int* outlen); // config: SHA1, SHA256, SHA512, RIPEMD160
int privmxDrvCrypto_hmac(const char* key, unsigned int keylen, const char* data, int datalen, const char* config, char** out, unsigned int* outlen); // config: SHA1, SHA256, SHA512
int privmxDrvCrypto_aesEncrypt(const char* key, const char* iv, const char* data, unsigned int datalen, const char* config, char** out, unsigned int* outlen); // config: AES-256-ECB-NOPAD, AES-256-CBC, AES-256-CBC-NOPAD
int privmxDrvCrypto_aesDecrypt(const char* key, const char* iv, const char* data, unsigned int datalen, const char* config, char** out, unsigned int* outlen); // config: AES-256-ECB-NOPAD, AES-256-CBC, AES-256-CBC-NOPAD
int privmxDrvCrypto_pbkdf2(const char* pass, unsigned int passlen, const char* salt, unsigned int saltlen, int rounds, unsigned int length, const char* hash, char** out, unsigned int* outlen);
int privmxDrvCrypto_freeMem(void* ptr);

#ifdef __cplusplus
}
#endif

#endif // __PRIVMX_DRIVER_CRYPTO_H__
