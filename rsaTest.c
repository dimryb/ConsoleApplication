#include "rsaTest.h"

#include "mbedtls/rsa.h"
#include "mbedtls/rsa_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/sha1.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

/*
 * Example RSA-1024 keypair, for test purposes
 */
#if 1
#define KEY_LEN 256

#define RSA_N   "B7C04786103AB2E2FF44C9E733F962C1BFD0B5FD1BC4C5F350A1506FD69608E8178B2DE3C8742C3C4CAF2588D2A29E0DA54FC417E573B11DDBB5AC3EF7ADC688358235D56E7E91D3429434581D0B73DD73B5235EC2F11BBDAC233AE59CDED0922FB6BAE24529AF50CC97A08C91F39BB825011027DC223D4A0A3D8A263C59DC5AA3CD2159225FFDC99009A93573D079E158492C1F4D8A3467AB7E35D33A0C6A3FD6982DED3658DCF6C44D65CEFCBCE4A0AA40AAC12BA6CC33B8801C280A200FBCAA745C605626A22D2E70031D894F73FC85AE662F50909E77FD33484B2AFBA43F22A1BD095EA00CE768A855C353FBB3F99222525A7CADFADB8B25AAE13C47486B"

#define RSA_E   "10001"

#define RSA_D   "0B323F696F1926D0F9C654D0D2F40D4D25CE81AF26A3DCEC7E0FF3F49EDE840F8F25684ED8662177E3B3B7CC7CE5BC0521B1AB459332059935706BB84311393058EEE49DB43A041AADB8DEF1593BB6B2ECAE1D480B9885AF33AFCA6E36F60E63AE829848474125FA463F6660D37C6937E7A399A88D3FFA8EA1171BB5B593FA6CBE149AEAF9FF3B797380DAAF2F4DF8259BA649D2E3B7827F123F8A084E0B3F8E04D2AB44E51891022BC302DFD7266CDB1F9232252ABFEDA7D48EFC9EB8F9C7C99499763BF7F232BBFD34414029619872AC14322F30520AFDD5EF8038D35E79C2FF54B4D63156460C0E0765A66A8EC7999DA4BFE3CF6B29D727823F9EC8DC6B79"

#define RSA_P   "EA11BBF294D7FE47F0A18C39E0DA79D347EB677ECDD2FA1184C9C5C8D3F405D9C89AE117EFC9C86748782BAB5BF68FBD0EEF364D525EE937A4B1F98EA0077EA0BB531DFF35FF28BEAEC5844A1C293B5C94CB435A455D5770DD80E5E56E661D0F028DBAF63C5B97E0528829F5EA0AD0514CDBD0E0BDC7BE4A46867C70DC01686D"

#define RSA_Q   "C8F7A397EE2A26A434A12F36D8CAAE296306A4992EF5D8EB79645969565824103312A45E31FA6F800EC3D98C344BFA2DA4563E98E1D8C7CF328D4D3FDD1C01D7946A35733398788351BD7A8F1572852BA009A5DA4701CB39BA4B2B90811C0B80D4B28B6D5BD7C07616A56CF4F474AF35D2AA0A33144F8A250F3B20EDAF4B9D37"

#define PT_LEN  11
#define RSA_PT  "Hello RSA!"

#else
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"
#endif



#if defined(MBEDTLS_PKCS1_V15)
static int myrand(void* rng_state, unsigned char* output, size_t len)
{
    size_t i;

    if (rng_state != NULL)
        rng_state = NULL;

    for (i = 0; i < len; ++i)
        output[i] = 45; rand();

    return(0);
}
#endif /* MBEDTLS_PKCS1_V15 */

int rsa_importKey(mbedtls_rsa_context* rsa, const char* strN, const char* strP, const char* strQ, const char* strD, const char* strE) {
    int ret = 0;
    mbedtls_mpi K;

    mbedtls_printf("  RSA key import: ");

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

    ret |= mbedtls_mpi_read_string(&K, 16, strN);
    ret |= mbedtls_rsa_import(rsa, &K, NULL, NULL, NULL, NULL);
    ret |= mbedtls_mpi_read_string(&K, 16, strP);
    ret |= mbedtls_rsa_import(rsa, NULL, &K, NULL, NULL, NULL);
    ret |= mbedtls_mpi_read_string(&K, 16, strQ);
    ret |= mbedtls_rsa_import(rsa, NULL, NULL, &K, NULL, NULL);
    ret |= mbedtls_mpi_read_string(&K, 16, strD);
    ret |= mbedtls_rsa_import(rsa, NULL, NULL, NULL, &K, NULL);
    ret |= mbedtls_mpi_read_string(&K, 16, strE);
    ret |= mbedtls_rsa_import(rsa, NULL, NULL, NULL, NULL, &K);

    ret |= mbedtls_rsa_complete(rsa);

    mbedtls_mpi_free(&K);

    if (ret) {
        mbedtls_printf("failed\n");
    } else {
        mbedtls_printf("passed\n");
    }

    return ret;
}

int rsa_keyValidation(mbedtls_rsa_context* rsa) {
    int ret = 0;
    mbedtls_printf("  RSA key validation: ");

    if (mbedtls_rsa_check_pubkey(rsa) != 0 ||
        mbedtls_rsa_check_privkey(rsa) != 0) {
        mbedtls_printf("failed\n");
        ret |= 1;
    }
    else {
        mbedtls_printf("passed\n");
    }

    return ret;
}

int rsa_encrypt(mbedtls_rsa_context *rsa, size_t len, unsigned char *rsa_plaintext, unsigned char* rsa_ciphertext) {
    mbedtls_printf("  PKCS#1 encryption : ");
    int ret = mbedtls_rsa_pkcs1_encrypt(rsa, myrand, NULL, MBEDTLS_RSA_PUBLIC, len, rsa_plaintext,  rsa_ciphertext);
    if (ret == 0) {
        mbedtls_printf("passed, MSG: %s\n", rsa_plaintext);
    } else {
        mbedtls_printf("failed\n");
    }
    return ret;
}

/*
 * Checkup routine
 */
int rsa_test()
{
    int ret = 0;
#if defined(MBEDTLS_PKCS1_V15)
    size_t len;
    mbedtls_rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];

    if (rsa_importKey(&rsa, RSA_N, RSA_P, RSA_Q, RSA_D, RSA_E) != 0) {
        ret = 1;
        goto cleanup;
    }

    if (rsa_keyValidation(&rsa) != 0) {
        ret = 1;
        goto cleanup;
    }

    memcpy(rsa_plaintext, RSA_PT, PT_LEN);

    if (rsa_encrypt(&rsa, PT_LEN, rsa_plaintext, rsa_ciphertext) != 0) {
        ret = 1;
        goto cleanup;
    }

    mbedtls_printf("  PKCS#1 decryption : ");

    if (mbedtls_rsa_pkcs1_decrypt(&rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE,
        &len, rsa_ciphertext, rsa_decrypted,
        sizeof(rsa_decrypted)) != 0)
    {
        mbedtls_printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    if (memcmp(rsa_decrypted, rsa_plaintext, len) != 0)
    {
        mbedtls_printf("failed\n");

        ret = 1;
        goto cleanup;
    }

    mbedtls_printf("passed, MSG: %s\n", rsa_decrypted);
    mbedtls_printf("\n");

cleanup:    
    mbedtls_rsa_free(&rsa);

#endif

    return(ret);
}
