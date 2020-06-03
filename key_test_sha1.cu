#include <cstdint>
#include <iostream>
#include <algorithm>
#include "key_test.hpp"
#include "error_check.hpp"

#ifndef LROT32
#define LROT32(x, n) (((x)<<(n))|((x)>>(32-(n))))
#endif

// DSA, no key should be longer
__constant__ uint32_t chunk_buffer[208];

__global__
void proc_chunk(
        size_t chunk_idx,
        uint32_t keytime,
        uint32_t *h0,
        uint32_t *h1,
        uint32_t *h2,
        uint32_t *h3,
        uint32_t *h4) {
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t a, b, c, d, e;

    uint32_t w[16];
    memcpy(w, chunk_buffer + chunk_idx * 16, sizeof(w));

    if (chunk_idx == 0) {
        w[1] = keytime - index;
        h0[index] = 0x67452301;
        h1[index] = 0xEFCDAB89;
        h2[index] = 0x98BADCFE;
        h3[index] = 0x10325476;
        h4[index] = 0xC3D2E1F0;
    }

    a = h0[index];
    b = h1[index];
    c = h2[index];
    d = h3[index];
    e = h4[index];

#pragma unroll
    for (int i=0; i<80; i++) {
        uint32_t f, k;

        if (i < 20) {
            f = d ^ (b & (c ^ d));
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t wi;
        if (i < 16)
            wi = w[i];
        else
            wi = w[i%16] = LROT32(w[(i-3)%16] ^ w[(i-8)%16] ^ w[(i-14)%16] ^ w[i%16], 1);

        uint32_t temp = LROT32(a, 5) + f + e + k + wi;
        e = d;
        d = c;
        c = LROT32(b, 30);
        b = a;
        a = temp;
    }

    h0[index] += a;
    h1[index] += b;
    h2[index] += c;
    h3[index] += d;
    h4[index] += e;
}

size_t load_key(const std::vector<uint8_t> &pubkey) {
    std::vector<uint8_t> buf = pubkey;
    uint64_t buf_len = buf.size();

    // sha-1 padding
    auto pad_zero = (56 - (buf_len + 1) % 64) % 64;
    auto buf_len2 = buf_len + 1 + pad_zero + 8;

    buf.push_back(0x80);
    buf.resize(buf_len2, 0);

    buf_len *= 8;
    for (auto it = buf.rbegin(); buf_len && it != buf.rend(); it++) {
        *it = buf_len & 0xff;
        buf_len >>= 8;
    }

    // group buffer to 32-bit words
    for (int i = 0; i < buf_len2; i += 4) {
        std::swap(buf[i], buf[i + 3]);
        std::swap(buf[i + 1], buf[i + 2]);
    }

    DIE_ON_ERR(sizeof(chunk_buffer) >= buf_len2);
    CU_CALL(cudaMemcpyToSymbol, chunk_buffer, buf.data(), buf_len2, 0, cudaMemcpyHostToDevice);  

    return buf_len2 / 64;
}
