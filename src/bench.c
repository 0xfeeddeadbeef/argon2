/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <intrin.h>
#endif

#include "argon2.h"
#include "encoding.h"

static uint64_t rdtsc(void) {
#ifdef _WIN32
    return __rdtsc();
#else
#if defined(__amd64__) || defined(__x86_64__)
    uint64_t rax, rdx;
    __asm__ __volatile__("rdtsc" : "=a"(rax), "=d"(rdx) : :);
    return (rdx << 32) | rax;
#elif defined(__i386__) || defined(__i386) || defined(__X86__)
    uint64_t rax;
    __asm__ __volatile__("rdtsc" : "=A"(rax) : :);
    return rax;
#else
#error "Not implemented!"
#endif
#endif
}

/*
 * Benchmarks Argon2 with salt length 16, password length 16, t_cost 3,
   and different m_cost and threads
 */
static void benchmark() {
#define BENCH_OUTLEN 16
#define BENCH_INLEN 16
    const uint32_t inlen = BENCH_INLEN;
    const unsigned outlen = BENCH_OUTLEN;
    unsigned char out[BENCH_OUTLEN];
    unsigned char pwd_array[BENCH_INLEN];
    unsigned char salt_array[BENCH_INLEN];
#undef BENCH_INLEN
#undef BENCH_OUTLEN

    uint32_t t_cost = 3;
    uint32_t m_cost;
    uint32_t thread_test[4] = {1, 2, 4,  8};
    argon2_type types[3] = {Argon2_i, Argon2_d, Argon2_id};

    memset(pwd_array, 0, inlen);
    memset(salt_array, 1, inlen);

    for (m_cost = (uint32_t)1 << 10; m_cost <= (uint32_t)1 << 22; m_cost *= 2) {
        unsigned i;
        for (i = 0; i < 4; ++i) {
            double run_time = 0;
            uint32_t thread_n = thread_test[i];

            unsigned j;
            for (j = 0; j < 3; ++j) {
                clock_t start_time, stop_time;
                uint64_t start_cycles, stop_cycles;
                uint64_t delta;
                double mcycles;

                argon2_type type = types[j];
                start_time = clock();
                start_cycles = rdtsc();

                argon2_hash(t_cost, m_cost, thread_n, pwd_array, inlen,
                            salt_array, inlen, out, outlen, NULL, 0, type,
                            ARGON2_VERSION_NUMBER);

                stop_cycles = rdtsc();
                stop_time = clock();

                delta = (stop_cycles - start_cycles) / (m_cost);
                mcycles = (double)(stop_cycles - start_cycles) / (1UL << 20);
                run_time += ((double)stop_time - start_time) / (CLOCKS_PER_SEC);

                printf("%s %d iterations  %d MiB %d threads:  %2.2f cpb %2.2f "
                       "Mcycles \n", argon2_type2string(type, 1), t_cost,
                       m_cost >> 10, thread_n, (float)delta / 1024, mcycles);
            }

            printf("%2.4f seconds\n\n", run_time);
        }
    }
}

#define ARRAYSIZE(A)  (sizeof(A)/sizeof((A)[0]))

static char pwdBytes[] = "P@$5w0rd";
static char saltBytes[] = { 0xFF, 0x02, 0x01, 0x0D, 0xFF, 0x02, 0x01, 0xAA, 0xBB, 0xFF, 0xEE, 0x11, 0x22, 0x11, 0x22, 0x33 };

int main() {
    //benchmark();

    const uint32_t t_cost = 5;
    const uint32_t m_cost = 7168;
    const uint32_t p_cost = 1;
    const uint32_t hash_size = 32;
    const uint32_t pwd_size = sizeof(pwdBytes);
    void* pwd = &pwdBytes[0];
    void* salt = &saltBytes[0];
    uint32_t salt_size = sizeof(saltBytes);

    //
    // Hashing
    //

    // enc_len includes terminating zero
    size_t enc_len = argon2_encodedlen(t_cost, m_cost, p_cost, salt_size, hash_size, Argon2_id);
    printf_s("argon2_encodedlen() -> %zu bytes\r\n", enc_len);
    char* encoded = (char*)calloc(enc_len, sizeof(char));
    if (NULL == encoded)
    {
        fprintf_s(stderr, "ERROR: Insufficient memory\r\n");
        fflush(stderr);
        return 1;
    }

    int arg_err = argon2id_hash_encoded(t_cost, m_cost, p_cost,
                                        pwd, pwd_size,
                                        salt, salt_size,
                                        hash_size,
                                        encoded, enc_len);
    if (ARGON2_OK == arg_err)
    {
        printf_s("argon2id_hash_encoded() -> '%s'\r\n", encoded);
    }
    else
    {
        fprintf_s(stderr, "argon2_error_message() -> '%s'\r\n", argon2_error_message(arg_err));
        fflush(stderr);
    }

    //
    // Verification
    //
    arg_err = argon2id_verify(encoded, pwd, pwd_size);
    if (ARGON2_OK == arg_err)
    {
        printf_s("argon2id_verify() -> 'OK'\r\n");
    }
    else
    {
        fprintf_s(stderr, "argon2_error_message() -> '%s'\r\n", argon2_error_message(arg_err));
        fflush(stderr);
    }

    free((void*)encoded);

    //
    // Example: Using context, secret and additional data
    //
    uint8_t outHash[32]    = { 0 };
    uint8_t secretData[16] = { 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32 };
    uint8_t addData[16]    = { 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32 };

    printf_s("sizeof(outHash)       => %zu bytes\r\n", sizeof(outHash));
    printf_s("ARRAYSIZE(outHash)    => %zu bytes\r\n", ARRAYSIZE(outHash));
    printf_s("sizeof(secretData)    => %zu bytes\r\n", sizeof(secretData));
    printf_s("ARRAYSIZE(secretData) => %zu bytes\r\n", ARRAYSIZE(secretData));
    printf_s("sizeof(addData)       => %zu bytes\r\n", sizeof(addData));
    printf_s("ARRAYSIZE(addData)    => %zu bytes\r\n", ARRAYSIZE(addData));

    argon2_context* ctx = (argon2_context*)malloc(sizeof(argon2_context));
    if (ctx) {
        ctx->out          = outHash;
        ctx->outlen       = sizeof(outHash);
        ctx->pwd          = pwd;
        ctx->pwdlen       = pwd_size;
        ctx->salt         = salt;
        ctx->saltlen      = salt_size;
        ctx->secret       = secretData;
        ctx->secretlen    = sizeof(secretData);
        ctx->ad           = addData;
        ctx->adlen        = sizeof(addData);
        ctx->t_cost       = t_cost;
        ctx->m_cost       = m_cost;
        ctx->lanes        = p_cost;
        ctx->threads      = p_cost;
        ctx->version      = ARGON2_VERSION_13;
        ctx->allocate_cbk = NULL;
        ctx->free_cbk     = NULL;
        ctx->flags        = ARGON2_DEFAULT_FLAGS;
    }
    else {
        fprintf_s(stderr, "ERROR: Insufficient memory.\r\n");
        fflush(stderr);
        return 2;
    }

    arg_err = argon2id_ctx(ctx);
    if (ARGON2_OK == arg_err)
    {
        char* ctx_encoded = (char*)calloc(enc_len, sizeof(char));
        arg_err = encode_string(ctx_encoded, enc_len, ctx, Argon2_id);
        if (arg_err == ARGON2_OK)
        {
            printf_s("argon2id_ctx() -> '%s'\r\n", ctx_encoded);
        }
        else
        {
            fprintf_s(stderr, "argon2_error_message() -> '%s'\r\n", argon2_error_message(arg_err));
            fflush(stderr);
        }
        free((void*)ctx_encoded);
    }
    else
    {
        fprintf_s(stderr, "argon2_error_message() -> '%s'\r\n", argon2_error_message(arg_err));
        fflush(stderr);
    }

    //
    // Verify context
    //

    // BUG: Weird bahevior!!! secret and ad not taken into account when verifying
    ctx->secret = NULL;
    ctx->secretlen = 0U;
    ctx->ad = NULL;
    ctx->adlen = 0U;

    ctx->pwd = NULL;
    ctx->pwdlen = 0U;
    //ctx->out = NULL;
    //ctx->outlen = 0U;

    //arg_err = argon2id_verify_ctx(ctx, outHash);
    arg_err = argon2_verify_ctx(ctx, outHash, Argon2_id);
    if (ARGON2_OK == arg_err)
    {
        printf_s("argon2id_verify_ctx() -> 'VERIFIED'\r\n");
    }
    else
    {
        fprintf_s(stderr, "argon2_error_message() -> '%s'\r\n", argon2_error_message(arg_err));
        fflush(stderr);
    }

    free((void*)ctx);
    int ch = getchar();

    //return ARGON2_OK;
    return arg_err;
}
