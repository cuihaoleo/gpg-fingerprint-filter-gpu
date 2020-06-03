#include "key_test.hpp"

#include <cctype>
#include <cstdint>
#include <string>

#define PATTERN_LIMIT 8

__constant__ uint8_t pattern_buffer[PATTERN_LIMIT][40];
__constant__ int num_pattern;

__global__
void gpu_pattern_check(
        uint32_t *retval,
        uint32_t *h0,
        uint32_t *h1,
        uint32_t *h2,
        uint32_t *h3,
        uint32_t *h4) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t tmp;
    uint8_t w[40];
    const uint32_t *(h[5]) = {h0, h1, h2, h3, h4};

    // I assumed CUDA is little-endian
#pragma unroll
    for (int i=0; i<5; i++) {
        tmp = h[i][index];
#pragma unroll
        for (int j=7; j>=0; j--) {
            w[i*8 + j] = tmp & 0x0000000F;
            tmp >>= 4;
        }
    }

    uint8_t symbol_map[36];

#pragma unroll
    for (int i=0; i<16; i++)
        symbol_map[i] = i;

#pragma unroll
    for (int i=16; i<sizeof(symbol_map); i++)
        symbol_map[i] = 0xFF;

    bool flag_ok = false;
    for (int i = 0; i < num_pattern && !flag_ok; i++) {
        for (int j = 39; j >= 0; j--) {
            uint8_t symbol = pattern_buffer[i][j];

            if (symbol == 0xFF) {
                flag_ok = true;
                break;
            }

            if (symbol_map[symbol] == 0xFF)
                symbol_map[symbol] = w[j];
            else if (symbol_map[symbol] != w[j])
                break;
        }
    }

    if (flag_ok)
        *retval = index;
}

static bool compile_pattern(const char *pattern, uint8_t *output) {
    uint8_t tmp_out[40];
    int idx = 0;
    int bra = -1, ket = -1;
    const char *p;

    for (p = pattern; *p; p++) {
        switch (*p) {
            case '(': {
                if (bra == -1)
                    bra = idx;
                else
                    return false;

                break;
            };
            case ')': {
                if (bra != -1)
                    ket = idx;
                else
                    return false;

                break;
            }
            case '{': {
                unsigned long num = strtoul(++p, (char**)&p, 10);

                if (*p != '}' || num == 0)
                    return false;

                int i0, i1;
                if (ket == -1) {
                    i0 = idx - 1;
                    i1 = idx;
                } else {
                    i0 = bra;
                    i1 = ket;
                    bra = ket = -1;
                }

                for (unsigned long i = 0; i < num - 1; i++) {
                    for (int j = i0; j < i1; j++) {
                        if (idx >= 40)
                            return false;

                        tmp_out[idx++] = tmp_out[j];
                    }
                }

                break;
            }
            default: {
                if (idx >= 40)
                    return false;

                if (isdigit(*p))
                    tmp_out[idx++] = *p - '0';
                else if (isupper(*p))
                    tmp_out[idx++] = *p - 'A' + 10;
                else
                    return false;

                if (ket != -1)
                    bra = ket = -1;
            }
        };
    }

    if (bra != -1 && ket == -1)
        return false;

    memset(output, 0xFF, 40 - idx);
    memcpy(output + (40 - idx), tmp_out, idx);

    return true;
}

void load_patterns(const std::string input) {
    size_t pos = 0;
    int count = 0;
    std::string buffer = input + "|";
    std::string pattern;
    uint8_t compiled[8][40];

    while ((pos = buffer.find("|")) != std::string::npos) {
        pattern = buffer.substr(0, pos);
        buffer.erase(0, pos + 1);

        if (count == PATTERN_LIMIT)
            throw std::runtime_error("too many patterns");

        DIE_ON_ERR(compile_pattern(pattern.c_str(), compiled[count++]));
    }

    CU_CALL(cudaMemcpyToSymbol, pattern_buffer, compiled, sizeof(compiled));
    CU_CALL(cudaMemcpyToSymbol, num_pattern, &count, sizeof(num_pattern));
};
