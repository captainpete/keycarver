// secp256k1 elliptic curve point arithmetic (Jacobian coordinates)
#pragma once
#include "secp256k1_field.cuh"
#include <stdint.h>

typedef struct { fe x, y, z; } JacobianPoint;
typedef struct { fe x, y; } AffinePoint;

// secp256k1 curve order n (for validity checking)
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// As little-endian u32:
__device__ static const uint32_t CURVE_N[8] = {
    0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

// Check if sk_bytes (big-endian, 32 bytes) is zero or >= n
// Returns true if the key is valid (nonzero and < n)
__device__ __inline__ bool sk_is_valid(const uint8_t* sk_bytes) {
    // Convert big-endian bytes to little-endian u32 limbs
    uint32_t sk[8];
    for (int i = 0; i < 8; i++) {
        // sk_bytes[0..3] = most significant bytes -> sk[7]
        int b = (7 - i) * 4;
        sk[i] = ((uint32_t)sk_bytes[b    ] << 24) |
                ((uint32_t)sk_bytes[b + 1] << 16) |
                ((uint32_t)sk_bytes[b + 2] <<  8) |
                ((uint32_t)sk_bytes[b + 3]      );
    }

    // Check not zero
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) acc |= sk[i];
    if (acc == 0) return false;

    // Check < n (using borrow-chain subtraction sk - n)
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)sk[i] - CURVE_N[i] - borrow;
        borrow = (diff >> 63) & 1;
    }
    // If borrow==1, sk < n (valid); if borrow==0, sk >= n (invalid)
    return borrow == 1;
}

// Standard Jacobian point doubling for a=0 curve (secp256k1)
// Formula from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
// W = 3*X1^2
// S = Y1*Z1
// B = X1*Y1*S
// H = W^2 - 8*B
// X3 = 2*H*S
// Y3 = W*(4*B - H) - 8*Y1^2*S^2
// Z3 = 8*S^3
__device__ __inline__ JacobianPoint point_double(JacobianPoint p) {
    fe X1 = p.x, Y1 = p.y, Z1 = p.z;

    fe W  = field_mul3(field_sqr(X1));                  // W = 3*X1^2
    fe S  = field_mul(Y1, Z1);                          // S = Y1*Z1
    fe B  = field_mul(field_mul(X1, Y1), S);            // B = X1*Y1*S
    fe W2 = field_sqr(W);                               // W^2
    fe B8 = field_mul8(B);                              // 8*B
    fe H  = field_sub(W2, B8);                          // H = W^2 - 8*B
    fe HS = field_mul(H, S);                            // H*S
    fe X3 = field_add(HS, HS);                          // X3 = 2*H*S

    fe B4 = field_add(field_add(B, B), field_add(B, B)); // 4*B
    fe Y1S = field_mul(Y1, S);                          // Y1*S
    fe Y1S2 = field_sqr(Y1S);                           // Y1^2 * S^2
    fe Y3 = field_sub(
        field_mul(W, field_sub(B4, H)),
        field_mul8(Y1S2)
    );                                                  // W*(4*B-H) - 8*Y1^2*S^2

    fe S2 = field_sqr(S);                               // S^2
    fe S3 = field_mul(S2, S);                           // S^3
    fe Z3 = field_mul8(S3);                             // Z3 = 8*S^3

    JacobianPoint r = {X3, Y3, Z3};
    return r;
}

// Jacobian point addition
// Formula: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
// U1 = X1*Z2^2, U2 = X2*Z1^2
// S1 = Y1*Z2^3, S2 = Y2*Z1^3
// H = U2 - U1
// R = S2 - S1
// X3 = R^2 - H^3 - 2*U1*H^2
// Y3 = R*(U1*H^2 - X3) - S1*H^3
// Z3 = H*Z1*Z2
__device__ __inline__ JacobianPoint point_add(JacobianPoint p, JacobianPoint q) {
    fe X1 = p.x, Y1 = p.y, Z1 = p.z;
    fe X2 = q.x, Y2 = q.y, Z2 = q.z;

    fe Z1Z1 = field_sqr(Z1);
    fe Z2Z2 = field_sqr(Z2);
    fe U1   = field_mul(X1, Z2Z2);
    fe U2   = field_mul(X2, Z1Z1);
    fe S1   = field_mul(Y1, field_mul(Z2, Z2Z2));
    fe S2   = field_mul(Y2, field_mul(Z1, Z1Z1));

    fe H  = field_sub(U2, U1);
    fe R  = field_sub(S2, S1);

    fe H2 = field_sqr(H);
    fe H3 = field_mul(H, H2);

    fe U1H2 = field_mul(U1, H2);

    fe R2 = field_sqr(R);
    fe X3 = field_sub(field_sub(R2, H3), field_add(U1H2, U1H2));
    fe Y3 = field_sub(field_mul(R, field_sub(U1H2, X3)), field_mul(S1, H3));
    fe Z3 = field_mul(H, field_mul(Z1, Z2));

    JacobianPoint r = {X3, Y3, Z3};
    return r;
}

// Jacobian + Affine point addition (Z2=1 optimization)
// U1 = X1, U2 = X2*Z1^2
// S1 = Y1, S2 = Y2*Z1^3
// H = U2 - U1
// R = S2 - S1
// X3 = R^2 - H^3 - 2*U1*H^2
// Y3 = R*(U1*H^2 - X3) - S1*H^3
// Z3 = H*Z1
__device__ __inline__ JacobianPoint point_add_affine(JacobianPoint p, AffinePoint q) {
    fe X1 = p.x, Y1 = p.y, Z1 = p.z;
    fe X2 = q.x, Y2 = q.y;

    fe Z1Z1 = field_sqr(Z1);
    fe U1   = X1;
    fe U2   = field_mul(X2, Z1Z1);
    fe S1   = Y1;
    fe S2   = field_mul(Y2, field_mul(Z1, Z1Z1));

    fe H  = field_sub(U2, U1);
    fe R  = field_sub(S2, S1);

    fe H2 = field_sqr(H);
    fe H3 = field_mul(H, H2);
    fe U1H2 = field_mul(U1, H2);

    fe R2 = field_sqr(R);
    fe X3 = field_sub(field_sub(R2, H3), field_add(U1H2, U1H2));
    fe Y3 = field_sub(field_mul(R, field_sub(U1H2, X3)), field_mul(S1, H3));
    fe Z3 = field_mul(H, Z1);

    JacobianPoint r = {X3, Y3, Z3};
    return r;
}

// Convert Jacobian to Affine: (X:Y:Z) -> (X/Z^2, Y/Z^3)
__device__ __inline__ AffinePoint jacobian_to_affine(JacobianPoint p) {
    fe z_inv  = field_inv(p.z);
    fe z_inv2 = field_sqr(z_inv);
    fe z_inv3 = field_mul(z_inv2, z_inv);

    AffinePoint r;
    r.x = field_mul(p.x, z_inv2);
    r.y = field_mul(p.y, z_inv3);
    return r;
}

// Scalar multiply: result = sk * G using precomputed g_powers[i] = 2^i * G
// sk_bytes: 32 bytes big-endian
// g_powers: 256 JacobianPoints
// compressed_pk: 33-byte output
// Returns false if sk is invalid (zero or >= n)
__device__ __inline__ bool secp256k1_scalar_mult_G(
    const uint8_t* sk_bytes,
    const JacobianPoint* g_powers,
    uint8_t* compressed_pk)
{
    if (!sk_is_valid(sk_bytes)) return false;

    // Convert big-endian sk_bytes to little-endian limbs for bit extraction
    uint32_t sk[8];
    for (int i = 0; i < 8; i++) {
        int b = (7 - i) * 4;
        sk[i] = ((uint32_t)sk_bytes[b    ] << 24) |
                ((uint32_t)sk_bytes[b + 1] << 16) |
                ((uint32_t)sk_bytes[b + 2] <<  8) |
                ((uint32_t)sk_bytes[b + 3]      );
    }

    // Double-and-add using precomputed powers of 2
    // result = sum of g_powers[i] where bit i of sk is set
    bool has_result = false;
    JacobianPoint result;

    for (int i = 0; i < 256; i++) {
        int limb = i / 32;
        int bit  = i % 32;
        if ((sk[limb] >> bit) & 1) {
            if (!has_result) {
                result = g_powers[i];
                has_result = true;
            } else {
                result = point_add(result, g_powers[i]);
            }
        }
    }

    if (!has_result) return false;  // sk was zero (already checked, but just in case)

    AffinePoint aff = jacobian_to_affine(result);

    // Encode compressed public key
    // prefix: 0x02 if Y is even (LSB=0), 0x03 if odd (LSB=1)
    compressed_pk[0] = (aff.y.d[0] & 1) ? 0x03 : 0x02;

    // X in big-endian
    for (int i = 0; i < 8; i++) {
        int limb_idx = 7 - i;
        compressed_pk[1 + i*4    ] = (aff.x.d[limb_idx] >> 24) & 0xFF;
        compressed_pk[1 + i*4 + 1] = (aff.x.d[limb_idx] >> 16) & 0xFF;
        compressed_pk[1 + i*4 + 2] = (aff.x.d[limb_idx] >>  8) & 0xFF;
        compressed_pk[1 + i*4 + 3] = (aff.x.d[limb_idx]      ) & 0xFF;
    }

    return true;
}
