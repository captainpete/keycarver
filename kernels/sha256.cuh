// SHA-256 implementation for CUDA
#pragma once
#include <stdint.h>
#include <string.h>

__device__ static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(e, f, g)  (((e) & (f)) ^ (~(e) & (g)))
#define SHA256_MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define SHA256_EP0(a) (SHA256_ROTR(a, 2) ^ SHA256_ROTR(a, 13) ^ SHA256_ROTR(a, 22))
#define SHA256_EP1(e) (SHA256_ROTR(e, 6) ^ SHA256_ROTR(e, 11) ^ SHA256_ROTR(e, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

__device__ __inline__ void sha256_process_block(uint32_t* state, const uint8_t* block) {
    uint32_t w[64];

    // Prepare message schedule (big-endian)
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4    ] << 24) |
               ((uint32_t)block[i*4 + 1] << 16) |
               ((uint32_t)block[i*4 + 2] <<  8) |
               ((uint32_t)block[i*4 + 3]      );
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + SHA256_K[i] + w[i];
        uint32_t t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha256(const uint8_t* input, uint32_t len, uint8_t* output) {
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    uint8_t block[64];
    uint32_t num_blocks = (len + 9 + 63) / 64;  // blocks needed (including padding)
    uint32_t offset = 0;

    for (uint32_t blk = 0; blk < num_blocks; blk++) {
        // Fill block with message bytes, padding
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
        // Last block: append bit length as 64-bit big-endian
        if (blk == num_blocks - 1) {
            uint64_t bit_len = (uint64_t)len * 8;
            block[56] = (bit_len >> 56) & 0xFF;
            block[57] = (bit_len >> 48) & 0xFF;
            block[58] = (bit_len >> 40) & 0xFF;
            block[59] = (bit_len >> 32) & 0xFF;
            block[60] = (bit_len >> 24) & 0xFF;
            block[61] = (bit_len >> 16) & 0xFF;
            block[62] = (bit_len >>  8) & 0xFF;
            block[63] = (bit_len      ) & 0xFF;
        }
        sha256_process_block(state, block);
        offset += 64;
    }

    // Output in big-endian
    for (int i = 0; i < 8; i++) {
        output[i*4    ] = (state[i] >> 24) & 0xFF;
        output[i*4 + 1] = (state[i] >> 16) & 0xFF;
        output[i*4 + 2] = (state[i] >>  8) & 0xFF;
        output[i*4 + 3] = (state[i]      ) & 0xFF;
    }
}
