// RIPEMD-160 implementation for CUDA
// RIPEMD-160 uses little-endian 32-bit words
#pragma once
#include <stdint.h>

// RIPEMD-160 constants
#define RIPEMD160_KL0 0x00000000u
#define RIPEMD160_KL1 0x5A827999u
#define RIPEMD160_KL2 0x6ED9EBA1u
#define RIPEMD160_KL3 0x8F1BBCDCu
#define RIPEMD160_KL4 0xA953FD4Eu

#define RIPEMD160_KR0 0x50A28BE6u
#define RIPEMD160_KR1 0x5C4DD124u
#define RIPEMD160_KR2 0x6D703EF3u
#define RIPEMD160_KR3 0x7A6D76E9u
#define RIPEMD160_KR4 0x00000000u

#define RIPEMD160_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Boolean functions for each round
#define RIPEMD160_F(x, y, z) ((x) ^ (y) ^ (z))
#define RIPEMD160_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RIPEMD160_H(x, y, z) (((x) | ~(y)) ^ (z))
#define RIPEMD160_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RIPEMD160_J(x, y, z) ((x) ^ ((y) | ~(z)))

// Message word selection for left and right rounds
__device__ static const int RIPEMD160_ML[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
    3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
    1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
    4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};

__device__ static const int RIPEMD160_MR[80] = {
    5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
    6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
    8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

// Rotation amounts for left and right rounds
__device__ static const int RIPEMD160_SL[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};

__device__ static const int RIPEMD160_SR[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};

__device__ __inline__ void ripemd160_process_block(uint32_t* state, const uint32_t* w) {
    uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint32_t ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];

    uint32_t f, t;

    for (int i = 0; i < 80; i++) {
        int round = i / 16;

        // Left side
        if (round == 0)      f = RIPEMD160_F(bl, cl, dl);
        else if (round == 1) f = RIPEMD160_G(bl, cl, dl);
        else if (round == 2) f = RIPEMD160_H(bl, cl, dl);
        else if (round == 3) f = RIPEMD160_I(bl, cl, dl);
        else                 f = RIPEMD160_J(bl, cl, dl);

        uint32_t kl;
        if (round == 0)      kl = RIPEMD160_KL0;
        else if (round == 1) kl = RIPEMD160_KL1;
        else if (round == 2) kl = RIPEMD160_KL2;
        else if (round == 3) kl = RIPEMD160_KL3;
        else                 kl = RIPEMD160_KL4;

        t = al + f + w[RIPEMD160_ML[i]] + kl;
        t = RIPEMD160_ROTL(t, RIPEMD160_SL[i]) + el;
        al = el; el = dl; dl = RIPEMD160_ROTL(cl, 10); cl = bl; bl = t;

        // Right side
        if (round == 0)      f = RIPEMD160_J(br, cr, dr);
        else if (round == 1) f = RIPEMD160_I(br, cr, dr);
        else if (round == 2) f = RIPEMD160_H(br, cr, dr);
        else if (round == 3) f = RIPEMD160_G(br, cr, dr);
        else                 f = RIPEMD160_F(br, cr, dr);

        uint32_t kr;
        if (round == 0)      kr = RIPEMD160_KR0;
        else if (round == 1) kr = RIPEMD160_KR1;
        else if (round == 2) kr = RIPEMD160_KR2;
        else if (round == 3) kr = RIPEMD160_KR3;
        else                 kr = RIPEMD160_KR4;

        t = ar + f + w[RIPEMD160_MR[i]] + kr;
        t = RIPEMD160_ROTL(t, RIPEMD160_SR[i]) + er;
        ar = er; er = dr; dr = RIPEMD160_ROTL(cr, 10); cr = br; br = t;
    }

    uint32_t tmp = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = tmp;
}

__device__ void ripemd160(const uint8_t* input, uint32_t len, uint8_t* output) {
    uint32_t state[5] = {
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u
    };

    uint8_t block[64];
    uint32_t num_blocks = (len + 9 + 63) / 64;
    uint32_t offset = 0;

    for (uint32_t blk = 0; blk < num_blocks; blk++) {
        // Fill block with message bytes and padding
        for (int i = 0; i < 64; i++) {
            uint32_t pos = offset + i;
            if (pos < len) {
                block[i] = input[pos];
            } else if (pos == len) {
                block[i] = 0x80;
            } else {
                block[i] = 0x00;
            }
        }

        // Last block: append bit length as 64-bit little-endian (RIPEMD-160 is LE)
        if (blk == num_blocks - 1) {
            uint64_t bit_len = (uint64_t)len * 8;
            block[56] = (bit_len      ) & 0xFF;
            block[57] = (bit_len >>  8) & 0xFF;
            block[58] = (bit_len >> 16) & 0xFF;
            block[59] = (bit_len >> 24) & 0xFF;
            block[60] = (bit_len >> 32) & 0xFF;
            block[61] = (bit_len >> 40) & 0xFF;
            block[62] = (bit_len >> 48) & 0xFF;
            block[63] = (bit_len >> 56) & 0xFF;
        }

        // Load block as little-endian 32-bit words
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)block[i*4    ]      ) |
                   ((uint32_t)block[i*4 + 1] <<  8) |
                   ((uint32_t)block[i*4 + 2] << 16) |
                   ((uint32_t)block[i*4 + 3] << 24);
        }

        ripemd160_process_block(state, w);
        offset += 64;
    }

    // Output in little-endian
    for (int i = 0; i < 5; i++) {
        output[i*4    ] = (state[i]      ) & 0xFF;
        output[i*4 + 1] = (state[i] >>  8) & 0xFF;
        output[i*4 + 2] = (state[i] >> 16) & 0xFF;
        output[i*4 + 3] = (state[i] >> 24) & 0xFF;
    }
}
