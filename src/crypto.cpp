/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>
#include <string.h>
#include <memory>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>

#include "privmx/drv/crypto.h"

struct AesOptions
{
    std::string alg;
    bool padding;
};

AesOptions getOptions(const char* config) {
    std::string alg;
    bool padding = true;
    if (strcmp(config, "AES-256-CBC") == 0) {
        alg = "AES-256-CBC";
    } else if (strcmp(config, "AES-256-CBC-NOPAD") == 0) {
        alg = "AES-256-CBC";
        padding = false;
    } else if (strcmp(config, "AES-256-ECB-NOPAD") == 0) {
        alg = "AES-256-ECB";
        padding = false;
    }
    return {alg, padding};
}

int privmxDrvCrypto_version(unsigned int* version) {
    *version = 1;
    return 0;
}

int privmxDrvCrypto_randomBytes(char* buf, unsigned int len) {
    if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(buf), len) != 1) {
        return 1;
    }
    return 0;
}

int privmxDrvCrypto_md(const char* data, int datalen, const char* config, char** out, unsigned int* outlen) {
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> evp_md(EVP_MD_fetch(NULL, config, NULL), EVP_MD_free);
    if (evp_md.get() == NULL) {
        return 1;
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (ctx.get() == NULL) {
        return 2;
    }
    if (!EVP_DigestInit_ex2(ctx.get(), evp_md.get(), NULL)) {
        return 3;
    }
    if (!EVP_DigestUpdate(ctx.get(), data, datalen)) {
        return 4;
    }
    unsigned int len;
    unsigned char res[EVP_MAX_MD_SIZE];
    if (!EVP_DigestFinal_ex(ctx.get(), res, &len)) {
        return 5;
    }
    *out = reinterpret_cast<char*>(malloc(len));
    memcpy(*out, res, len);
    *outlen = len;
    return 0;
}

int privmxDrvCrypto_hmac(const char* key, unsigned int keylen, const char* data, int datalen, const char* config, char** out, unsigned int* outlen) {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> evp_mac(EVP_MAC_fetch(NULL, "HMAC", NULL), EVP_MAC_free);
    if (evp_mac.get() == NULL) {
        return 1;
    }
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(evp_mac.get()), EVP_MAC_CTX_free);
    if (ctx.get() == NULL) {
        return 2;
    }
    std::string digest(config);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest.data(), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(ctx.get(), reinterpret_cast<const unsigned char*>(key), keylen, params)) {
        return 3;
    }
    if (!EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char*>(data), datalen)) {
        return 4;
    }
    size_t len = EVP_MAC_CTX_get_mac_size(ctx.get());
    char* buf = reinterpret_cast<char*>(malloc(len));
    if (!EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char*>(buf), &len, len)) {
        return 6;
    }
    *out = buf;
    *outlen = len;
    return 0;
}

int privmxDrvCrypto_aesEncrypt(const char* key, const char* iv, const char* data, unsigned int datalen, const char* config, char** out, unsigned int* outlen) {
    auto options = getOptions(config);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(EVP_CIPHER_fetch(NULL, options.alg.c_str(), NULL), EVP_CIPHER_free);
    if (cipher.get() == NULL) {
        return 1;
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        return 2;
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    const unsigned char* k = reinterpret_cast<const unsigned char*>(key);
    const unsigned char* i = reinterpret_cast<const unsigned char*>(iv);
    if (EVP_EncryptInit_ex(raw_ctx, cipher.get(), NULL, k, i) != 1) {
        return 3;
    }
    if (!options.padding && EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        return 4;
    }
    unsigned char buf[datalen + EVP_CIPHER_block_size(cipher.get())];
    int buf_len = 0;
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data);
    if (EVP_EncryptUpdate(raw_ctx, buf, &buf_len, d, datalen) != 1) {
        return 5;
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
        return 6;
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    char* buf_as_char = reinterpret_cast<char*>(buf);
    *out = reinterpret_cast<char*>(malloc(buf_len));
    memcpy(*out, buf_as_char, buf_len);
    *outlen = buf_len;
    return 0;
}

int privmxDrvCrypto_aesDecrypt(const char* key, const char* iv, const char* data, unsigned int datalen, const char* config, char** out, unsigned int* outlen) {
    auto options = getOptions(config);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(EVP_CIPHER_fetch(NULL, options.alg.c_str(), NULL), EVP_CIPHER_free);
    if (cipher.get() == NULL) {
        return 1;
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    EVP_CIPHER_CTX* raw_ctx = ctx.get();
    if (raw_ctx == NULL) {
        return 2;
    }
    EVP_CIPHER_CTX_init(raw_ctx);
    const unsigned char* k = reinterpret_cast<const unsigned char*>(key);
    const unsigned char* i = reinterpret_cast<const unsigned char*>(iv);
    if (EVP_DecryptInit_ex(raw_ctx, cipher.get(), NULL, k, i) != 1) {
        return 3;
    }
    if (!options.padding && EVP_CIPHER_CTX_set_padding(raw_ctx, 0) != 1) {
        return 4;
    }
    unsigned char buf[datalen + EVP_CIPHER_block_size(cipher.get())];
    int buf_len = 0;
    const unsigned char* d = reinterpret_cast<const unsigned char*>(data);
    if (EVP_DecryptUpdate(raw_ctx, buf, &buf_len, d, datalen) != 1) {
        return 5;
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(raw_ctx, buf + buf_len, &final_len) != 1) {
        return 6;
    }
    buf_len += final_len;
    EVP_CIPHER_CTX_cleanup(raw_ctx);
    char* buf_as_char = reinterpret_cast<char*>(buf);
    *out = reinterpret_cast<char*>(malloc(buf_len));
    memcpy(*out, buf_as_char, buf_len);
    *outlen = buf_len;
    return 0;
}

int privmxDrvCrypto_pbkdf2(const char* pass, unsigned int passlen, const char* salt, unsigned int saltlen, int rounds, unsigned int length, const char* hash, char** out, unsigned int* outlen) {
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> evp_md(EVP_MD_fetch(NULL, hash, NULL), EVP_MD_free);
    if (evp_md.get() == NULL) {
        return 1;
    }
    std::string result(length, 0);
    const unsigned char *salt_as_uchars = reinterpret_cast<const unsigned char *>(salt);
    unsigned char *result_as_uchars = reinterpret_cast<unsigned char *>(result.data());
    if (PKCS5_PBKDF2_HMAC(pass, passlen, salt_as_uchars, saltlen, rounds, evp_md.get(), length, result_as_uchars) != 1) {
        return 2;
    }
    *out = reinterpret_cast<char*>(malloc(result.length()));
    memcpy(*out, result.data(), result.length());
    *outlen = length;
    return 0;
}

int privmxDrvCrypto_freeMem(void* ptr) {
    free(ptr);
    return 0;
}
