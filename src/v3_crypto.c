/*
 * v3_crypto.c - ChaCha20-Poly1305 + BLAKE2b
 */

#include "v3.h"

/* ============================================================
 * ChaCha20
 * ============================================================ */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while(0)

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);
    
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        load32_le(key), load32_le(key+4), load32_le(key+8), load32_le(key+12),
        load32_le(key+16), load32_le(key+20), load32_le(key+24), load32_le(key+28),
        counter, load32_le(nonce), load32_le(nonce+4), load32_le(nonce+8)
    };
    
    uint32_t block[16];
    uint8_t keystream[64];
    
    while (len > 0) {
        chacha20_block(block, state);
        for (int i = 0; i < 16; i++) store32_le(keystream + i*4, block[i]);
        
        size_t chunk = (len > 64) ? 64 : len;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = (in ? in[i] : 0) ^ keystream[i];
        }
        
        out += chunk; if (in) in += chunk; len -= chunk;
        state[12]++;
    }
}

/* ============================================================
 * Poly1305
 * ============================================================ */

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t buf[16];
    size_t leftover;
    int final;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    ctx->r[0] = load32_le(key) & 0x3ffffff;
    ctx->r[1] = (load32_le(key+3) >> 2) & 0x3ffff03;
    ctx->r[2] = (load32_le(key+6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (load32_le(key+9) >> 6) & 0x3f03fff;
    ctx->r[4] = (load32_le(key+12) >> 8) & 0x00fffff;
    
    memset(ctx->h, 0, sizeof(ctx->h));
    
    ctx->pad[0] = load32_le(key+16);
    ctx->pad[1] = load32_le(key+20);
    ctx->pad[2] = load32_le(key+24);
    ctx->pad[3] = load32_le(key+28);
    
    ctx->leftover = 0;
    ctx->final = 0;
}

static void poly1305_blocks(poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    uint32_t hibit = ctx->final ? 0 : (1 << 24);
    uint32_t r0=ctx->r[0], r1=ctx->r[1], r2=ctx->r[2], r3=ctx->r[3], r4=ctx->r[4];
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint32_t h0=ctx->h[0], h1=ctx->h[1], h2=ctx->h[2], h3=ctx->h[3], h4=ctx->h[4];
    
    while (bytes >= 16) {
        h0 += load32_le(m) & 0x3ffffff;
        h1 += (load32_le(m+3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m+6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m+9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m+12) >> 8) | hibit;
        
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        
        m += 16; bytes -= 16;
    }
    
    ctx->h[0]=h0; ctx->h[1]=h1; ctx->h[2]=h2; ctx->h[3]=h3; ctx->h[4]=h4;
}

static void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > bytes) want = bytes;
        memcpy(ctx->buf + ctx->leftover, m, want);
        m += want; bytes -= want; ctx->leftover += want;
        if (ctx->leftover < 16) return;
        poly1305_blocks(ctx, ctx->buf, 16);
        ctx->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~15;
        poly1305_blocks(ctx, m, want);
        m += want; bytes -= want;
    }
    if (bytes) {
        memcpy(ctx->buf, m, bytes);
        ctx->leftover = bytes;
    }
}

static void poly1305_finish(poly1305_ctx *ctx, uint8_t mac[16]) {
    if (ctx->leftover) {
        ctx->buf[ctx->leftover++] = 1;
        while (ctx->leftover < 16) ctx->buf[ctx->leftover++] = 0;
        ctx->final = 1;
        poly1305_blocks(ctx, ctx->buf, 16);
    }
    
    uint32_t h0=ctx->h[0], h1=ctx->h[1], h2=ctx->h[2], h3=ctx->h[3], h4=ctx->h[4];
    uint32_t c;
    
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);
    
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    
    uint64_t f;
    f = (uint64_t)h0 + ctx->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;
    
    store32_le(mac, h0 | (h1 << 26));
    store32_le(mac+4, (h1 >> 6) | (h2 << 20));
    store32_le(mac+8, (h2 >> 12) | (h3 << 14));
    store32_le(mac+12, (h3 >> 18) | (h4 << 8));
}

/* ============================================================
 * AEAD
 * ============================================================ */

int v3_aead_encrypt(uint8_t *ct, uint8_t tag[16],
                     const uint8_t *pt, size_t pt_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t nonce[12], const uint8_t key[32]) {
    /* 生成 Poly1305 密钥 */
    uint8_t poly_key[64] = {0};
    chacha20_xor(poly_key, NULL, 64, key, nonce, 0);
    
    /* 加密 */
    if (pt && pt_len > 0) {
        chacha20_xor(ct, pt, pt_len, key, nonce, 1);
    }
    
    /* 计算 MAC */
    poly1305_ctx ctx;
    poly1305_init(&ctx, poly_key);
    
    if (aad && aad_len > 0) {
        poly1305_update(&ctx, aad, aad_len);
        if (aad_len % 16) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (aad_len % 16));
        }
    }
    
    if (pt_len > 0) {
        poly1305_update(&ctx, ct, pt_len);
        if (pt_len % 16) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (pt_len % 16));
        }
    }
    
    uint8_t lens[16] = {0};
    for (int i = 0; i < 8; i++) {
        lens[i] = (aad_len >> (i * 8)) & 0xFF;
        lens[i + 8] = (pt_len >> (i * 8)) & 0xFF;
    }
    poly1305_update(&ctx, lens, 16);
    poly1305_finish(&ctx, tag);
    
    v3_secure_zero(poly_key, sizeof(poly_key));
    return V3_OK;
}

int v3_aead_decrypt(uint8_t *pt, const uint8_t *ct, size_t ct_len,
                     const uint8_t tag[16], const uint8_t *aad, size_t aad_len,
                     const uint8_t nonce[12], const uint8_t key[32]) {
    /* 生成 Poly1305 密钥 */
    uint8_t poly_key[64] = {0};
    chacha20_xor(poly_key, NULL, 64, key, nonce, 0);
    
    /* 验证 MAC */
    uint8_t computed[16];
    poly1305_ctx ctx;
    poly1305_init(&ctx, poly_key);
    
    if (aad && aad_len > 0) {
        poly1305_update(&ctx, aad, aad_len);
        if (aad_len % 16) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (aad_len % 16));
        }
    }
    
    if (ct && ct_len > 0) {
        poly1305_update(&ctx, ct, ct_len);
        if (ct_len % 16) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (ct_len % 16));
        }
    }
    
    uint8_t lens[16] = {0};
    for (int i = 0; i < 8; i++) {
        lens[i] = (aad_len >> (i * 8)) & 0xFF;
        lens[i + 8] = (ct_len >> (i * 8)) & 0xFF;
    }
    poly1305_update(&ctx, lens, 16);
    poly1305_finish(&ctx, computed);
    
    if (v3_secure_compare(tag, computed, 16) != 0) {
        v3_secure_zero(poly_key, sizeof(poly_key));
        return V3_ERR_AUTH_FAILED;
    }
    
    /* 解密 */
    if (pt && ct && ct_len > 0) {
        chacha20_xor(pt, ct, ct_len, key, nonce, 1);
    }
    
    v3_secure_zero(poly_key, sizeof(poly_key));
    return V3_OK;
}

/* ============================================================
 * BLAKE2b (简化版, 用于 Magic 派生)
 * ============================================================ */

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define G(r, i, a, b, c, d, m) do { \
    a += b + m[blake2b_sigma[r][2*i]]; d = ROTR64(d ^ a, 32); \
    c += d; b = ROTR64(b ^ c, 24); \
    a += b + m[blake2b_sigma[r][2*i+1]]; d = ROTR64(d ^ a, 16); \
    c += d; b = ROTR64(b ^ c, 63); \
} while(0)

static void blake2b_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint64_t h[8], v[16], m[16];
    uint8_t block[128] = {0};
    
    for (int i = 0; i < 8; i++) h[i] = blake2b_iv[i];
    h[0] ^= 0x01010000 ^ outlen;
    
    memcpy(block, in, inlen > 128 ? 128 : inlen);
    
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[i + 8] = blake2b_iv[i];
    v[12] ^= inlen;
    v[14] ^= ~0ULL;
    
    for (int i = 0; i < 16; i++) {
        m[i] = 0;
        for (int j = 0; j < 8; j++) m[i] |= ((uint64_t)block[i*8+j]) << (j*8);
    }
    
    for (int r = 0; r < 12; r++) {
        G(r, 0, v[0], v[4], v[8], v[12], m);
        G(r, 1, v[1], v[5], v[9], v[13], m);
        G(r, 2, v[2], v[6], v[10], v[14], m);
        G(r, 3, v[3], v[7], v[11], v[15], m);
        G(r, 4, v[0], v[5], v[10], v[15], m);
        G(r, 5, v[1], v[6], v[11], v[12], m);
        G(r, 6, v[2], v[7], v[8], v[13], m);
        G(r, 7, v[3], v[4], v[9], v[14], m);
    }
    
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    for (size_t i = 0; i < outlen; i++) out[i] = (h[i/8] >> (8*(i%8))) & 0xFF;
}

/* ============================================================
 * Magic 派生
 * ============================================================ */

uint32_t v3_derive_magic(const uint8_t key[V3_KEY_SIZE], uint64_t window) {
    uint8_t input[40];
    memcpy(input, key, 32);
    for (int i = 0; i < 8; i++) input[32 + i] = (window >> (i * 8)) & 0xFF;
    
    uint8_t hash[32];
    blake2b_hash(hash, 32, input, 40);
    
    return load32_le(hash);
}

uint32_t v3_current_magic(const uint8_t key[V3_KEY_SIZE]) {
    return v3_derive_magic(key, v3_time_sec() / V3_MAGIC_WINDOW_SEC);
}

bool v3_verify_magic(const uint8_t key[V3_KEY_SIZE], uint32_t magic, int tolerance) {
    uint64_t window = v3_time_sec() / V3_MAGIC_WINDOW_SEC;
    
    for (int offset = -tolerance; offset <= tolerance; offset++) {
        if (magic == v3_derive_magic(key, window + offset)) {
            return true;
        }
    }
    return false;
}
