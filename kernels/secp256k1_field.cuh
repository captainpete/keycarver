// secp256k1 field arithmetic over Fp = 2^256 - 2^32 - 977
// 8x32-bit limbs, little-endian: d[0] = least significant word
#pragma once
#include <stdint.h>

typedef struct { uint32_t d[8]; } fe;

// secp256k1 prime p = 2^256 - 2^32 - 977
// In little-endian u32: p[0]=0xFFFFFC2F, p[1]=0xFFFFFFFE, p[2..6]=0xFFFFFFFF, p[7]=0xFFFFFFFF
__device__ __constant__ static const fe FIELD_P = {{
    0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
}};

// n (curve order)
__device__ __constant__ static const fe FIELD_N = {{
    0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
}};

__device__ __inline__ fe fe_zero() {
    fe r;
    for (int i = 0; i < 8; i++) r.d[i] = 0;
    return r;
}

__device__ __inline__ fe fe_one() {
    fe r;
    r.d[0] = 1;
    for (int i = 1; i < 8; i++) r.d[i] = 0;
    return r;
}

// Compare: returns negative if a<b, 0 if equal, positive if a>b
__device__ __inline__ int fe_cmp(const fe* a, const fe* b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return  1;
    }
    return 0;
}

__device__ __inline__ int fe_is_zero(const fe* a) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) acc |= a->d[i];
    return acc == 0;
}

// Conditional subtract p: if a >= p, subtract p
__device__ __inline__ fe fe_reduce(fe a) {
    // subtract p with borrow; if borrow, restore
    uint64_t borrow = 0;
    fe t;
    const fe* p = &FIELD_P;
    for (int i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)a.d[i] - p->d[i] - borrow;
        t.d[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
    // if borrow==0, a>=p so use t; else use a
    return (borrow == 0) ? t : a;
}

__device__ __inline__ fe field_add(fe a, fe b) {
    fe r;
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)a.d[i] + b.d[i] + carry;
        r.d[i] = (uint32_t)s;
        carry = s >> 32;
    }
    // If carry==1 then a+b >= 2^256.
    // Since p = 2^256 - c (c = 2^32+977), we have 2^256 ≡ c (mod p).
    // So (a+b) mod p = r + c, where r = a+b - 2^256.
    // Add c = 2^32 + 977 to r to get the correct residue.
    if (carry) {
        // Add 977 to r.d[0], then add 1 to r.d[1] (for the 2^32 term)
        uint64_t s = (uint64_t)r.d[0] + 977u;
        r.d[0] = (uint32_t)s;
        s = (uint64_t)r.d[1] + 1u + (s >> 32);
        r.d[1] = (uint32_t)s;
        // Propagate carry
        for (int i = 2; i < 8 && (s >> 32); i++) {
            s = (uint64_t)r.d[i] + (s >> 32);
            r.d[i] = (uint32_t)s;
        }
        // Result is now r + c = a+b - p, which is in [0, p). No need to reduce.
        return r;
    }
    return fe_reduce(r);
}

__device__ __inline__ fe field_sub(fe a, fe b) {
    // a - b mod p = a + (p - b) if underflow, else a - b
    uint64_t borrow = 0;
    fe r;
    for (int i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)a.d[i] - b.d[i] - borrow;
        r.d[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
    if (borrow) {
        // add p back
        uint64_t carry = 0;
        const fe* p = &FIELD_P;
        for (int i = 0; i < 8; i++) {
            uint64_t s = (uint64_t)r.d[i] + p->d[i] + carry;
            r.d[i] = (uint32_t)s;
            carry = s >> 32;
        }
    }
    return r;
}

__device__ __inline__ fe field_neg(fe a) {
    if (fe_is_zero(&a)) return a;
    const fe* p = &FIELD_P;
    fe r;
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)p->d[i] - a.d[i] - borrow;
        r.d[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
    return r;
}

// Reduce a 512-bit number (16 limbs) mod p
// p = 2^256 - 2^32 - 977
// 2^256 ≡ 2^32 + 977 (mod p)
// so hi*2^256 ≡ hi*(2^32 + 977) (mod p)
__device__ __inline__ fe fe_reduce512(const uint32_t* t) {
    // t[0..15], lo=t[0..7], hi=t[8..15]
    // compute hi * (2^32 + 977):
    //   hi_shift32 = hi << 32 (shift hi by 1 limb)
    //   hi_977 = hi * 977
    // result = lo + hi_shift32 + hi_977
    // This may still be >= p so do one more conditional reduction

    // First compute lo + hi*(2^32 + 977)
    // hi*(2^32+977) = hi*2^32 + hi*977
    // hi*2^32 means we start adding from position 1 (shifted by one limb)

    uint64_t acc[9];  // 9 limbs to handle overflow (we produce up to 288 bits)
    for (int i = 0; i < 9; i++) acc[i] = 0;

    // Add lo
    for (int i = 0; i < 8; i++) acc[i] += (uint64_t)t[i];

    // Add hi * 977 (into positions 0..8)
    for (int i = 0; i < 8; i++) {
        acc[i] += (uint64_t)t[8 + i] * 977ULL;
    }

    // Add hi << 32 = hi shifted by 1 limb (into positions 1..9, but we only have 9)
    for (int i = 0; i < 8; i++) {
        acc[i + 1] += (uint64_t)t[8 + i];
    }

    // Propagate carries
    for (int i = 0; i < 8; i++) {
        acc[i + 1] += acc[i] >> 32;
        acc[i] &= 0xFFFFFFFFULL;
    }
    // acc[8] may have a small carry from propagation

    // Iteratively reduce remaining bits in acc[8].
    // acc[8] * 2^256 ≡ acc[8] * (2^32 + 977) (mod p).
    // Each iteration shrinks acc[8]; at most 3 iterations for typical inputs.
    uint64_t hi32;
    while ((hi32 = acc[8]) != 0) {
        acc[8] = 0;
        acc[0] += hi32 * 977ULL;
        acc[1] += hi32;
        for (int i = 0; i < 8; i++) {
            acc[i + 1] += acc[i] >> 32;
            acc[i] &= 0xFFFFFFFFULL;
        }
    }

    fe r;
    for (int i = 0; i < 8; i++) r.d[i] = (uint32_t)acc[i];

    // Final conditional reduction
    return fe_reduce(r);
}

// Schoolbook 8x8 multiply then reduce mod p
__device__ __inline__ fe field_mul(fe a, fe b) {
    uint32_t t[16];
    for (int i = 0; i < 16; i++) t[i] = 0;

    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t prod = (uint64_t)a.d[i] * b.d[j] + t[i + j] + carry;
            t[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        t[i + 8] += (uint32_t)carry;
    }

    return fe_reduce512(t);
}

__device__ __inline__ fe field_sqr(fe a) {
    return field_mul(a, a);
}

// Compute a^(p-2) mod p via binary exponentiation = modular inverse
// p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
__device__ __inline__ fe field_inv(fe a) {
    // p-2 in binary: we use a fixed addition chain
    // p - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
    // Use square-and-multiply with the bits of p-2
    // p-2 bits (from MSB): all 1s for 224 bits, then a special pattern
    // We use Fermat's: a^(p-2) = a^-1 mod p
    //
    // p-2 = p - 2:
    // p   = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    // p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D

    // Binary exponentiation over p-2
    // p-2 in u32 limbs (little-endian):
    uint32_t exp[8] = {
        0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
    };

    fe result = fe_one();
    fe base = a;

    for (int i = 0; i < 8; i++) {
        uint32_t limb = exp[i];
        for (int b = 0; b < 32; b++) {
            if (limb & 1) {
                result = field_mul(result, base);
            }
            base = field_sqr(base);
            limb >>= 1;
        }
    }
    return result;
}

__device__ __inline__ fe field_mul3(fe a) {
    return field_add(field_add(a, a), a);
}

__device__ __inline__ fe field_mul8(fe a) {
    fe r = field_add(a, a);   // 2*a
    r = field_add(r, r);      // 4*a
    return field_add(r, r);   // 8*a
}
