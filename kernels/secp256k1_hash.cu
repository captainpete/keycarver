#include "secp256k1_field.cuh"
#include "secp256k1_ec.cuh"
#include "sha256.cuh"
#include "ripemd160.cuh"
#include <string.h>

extern "C" __global__ void sk_to_pkh_kernel(
    const uint8_t* __restrict__ chunk,
    uint32_t chunk_len,
    uint8_t* __restrict__ out_pkhs,           // chunk_len * 20 bytes output
    const JacobianPoint* __restrict__ g_powers) // G, 2G, 4G, ..., 2^255*G
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= chunk_len) return;

    uint8_t sk[32];
    for (int i = 0; i < 32; i++) {
        sk[i] = (tid + i < chunk_len) ? chunk[tid + i] : 0;
    }

    uint8_t compressed_pk[33];
    bool valid = secp256k1_scalar_mult_G(sk, g_powers, compressed_pk);

    uint8_t* out = out_pkhs + (uint64_t)tid * 20;
    if (!valid) {
        memset(out, 0, 20);
        return;
    }

    uint8_t sha[32];
    sha256(compressed_pk, 33, sha);
    ripemd160(sha, 32, out);
}
