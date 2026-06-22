/* enc_dex.c — AES-256-CTR 加密 hooker.dex → hooker.dex.enc（[16B IV][密文]）
 *
 * 关键：#include 与 native 同一份 aes.c，CTR 计数器实现完全一致，绝不会解错。
 *
 * 编译（Linux/CI）:
 *   cc -O2 -I../app/src/main/cpp enc_dex.c ../app/src/main/cpp/aes.c -o enc_dex
 * 编译（Windows MSVC）:
 *   cl /O2 /I..\app\src\main\cpp enc_dex.c ..\app\src\main\cpp\aes.c
 * 用法:
 *   ./enc_dex hooker.dex hooker.dex.enc
 *   然后把 hooker.dex.enc 放到 pecker-agent 的 tools/peckerd/（不再发明文 hooker.dex）
 *
 * aes.h 已配 AES256 + CTR；KEY 必须与 hooks.cpp 的 DEX_KEY 逐字节一致。
 */
#define _CRT_RAND_S
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

/* ⚠⚠ 必须与 app/src/main/cpp/hooks.cpp 的 DEX_KEY 逐字节一致 */
static const uint8_t KEY[32] = {
    0xA4, 0xF5, 0x9A, 0x28, 0x1D, 0xEA, 0x66, 0x76,
    0xE9, 0x20, 0xFE, 0x49, 0x24, 0xC1, 0xC8, 0x9C,
    0x5F, 0xEE, 0xA4, 0x9B, 0x4B, 0xFC, 0x56, 0xBF,
    0x6D, 0x11, 0x3D, 0x0D, 0x44, 0xE6, 0xD5, 0x0C,
};

/* 16 字节随机 IV（CTR 模式下每次加密必须唯一，否则同 key 下密钥流复用会泄漏） */
static int fill_iv(uint8_t* iv) {
#ifdef _WIN32
    for (int i = 0; i < 16; i += 4) {
        unsigned int r;
        if (rand_s(&r) != 0) return -1;
        memcpy(iv + i, &r, 4);
    }
    return 0;
#else
    FILE* ur = fopen("/dev/urandom", "rb");
    if (!ur) return -1;
    size_t got = fread(iv, 1, 16, ur);
    fclose(ur);
    return got == 16 ? 0 : -1;
#endif
}

int main(int argc, char** argv) {
    if (argc != 3) { fprintf(stderr, "usage: enc_dex <in.dex> <out.enc>\n"); return 2; }

    FILE* in = fopen(argv[1], "rb");
    if (!in) { fprintf(stderr, "enc_dex: open %s failed\n", argv[1]); return 1; }
    fseek(in, 0, SEEK_END);
    long sz = ftell(in);
    fseek(in, 0, SEEK_SET);
    if (sz <= 0) { fprintf(stderr, "enc_dex: empty/invalid input\n"); fclose(in); return 1; }
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(in); return 1; }
    if (fread(buf, 1, (size_t)sz, in) != (size_t)sz) {
        fprintf(stderr, "enc_dex: read failed\n"); fclose(in); free(buf); return 1;
    }
    fclose(in);

    uint8_t iv[16];
    if (fill_iv(iv) != 0) { fprintf(stderr, "enc_dex: RNG failed\n"); free(buf); return 1; }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, KEY, iv);
    AES_CTR_xcrypt_buffer(&ctx, buf, (size_t)sz);

    FILE* out = fopen(argv[2], "wb");
    if (!out) { fprintf(stderr, "enc_dex: open %s failed\n", argv[2]); free(buf); return 1; }
    fwrite(iv, 1, 16, out);
    fwrite(buf, 1, (size_t)sz, out);
    fclose(out);
    free(buf);

    fprintf(stderr, "enc_dex: %ld bytes -> %s (+16B IV)\n", sz, argv[2]);
    return 0;
}
