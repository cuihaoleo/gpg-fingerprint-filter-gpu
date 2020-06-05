#include "key_test.hpp"

__constant__ static u8 pattern_buffer[PATTERN_LIMIT][40];
__constant__ static int num_pattern = 0;
__device__ static u32 result_index = UINT32_MAX;

__global__ static
void pattern_check(
        u32 *h0,
        u32 *h1,
        u32 *h2,
        u32 *h3,
        u32 *h4) {
    u32 index = blockIdx.x * blockDim.x + threadIdx.x;
    u32 tmp;
    u8 w[40];
    const u32 *(h[5]) = {h0, h1, h2, h3, h4};

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

    u8 symbol_map[36];

#pragma unroll
    for (int i=0; i<16; i++)
        symbol_map[i] = i;

#pragma unroll
    for (int i=16; i<sizeof(symbol_map); i++)
        symbol_map[i] = 0xFF;

    bool flag_ok = false;
    for (int i = 0; i < num_pattern && !flag_ok; i++)
        for (int j = 39; j >= 0; j--) {
            u8 symbol = pattern_buffer[i][j];

            if (symbol == 0xFF) {
                flag_ok = true;
                result_index = index;
                return;
            }

            if (symbol_map[symbol] == 0xFF)
                symbol_map[symbol] = w[j];
            else if (symbol_map[symbol] != w[j])
                break;
        }
}

static bool compile_pattern(const char *pattern, u8 *output) {
    u8 tmp_out[40];
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

void CudaManager::load_patterns(const std::string &input) {
    size_t pos = 0;
    int count = 0;
    std::string buffer = input + "|";
    std::string pattern;
    u8 compiled[8][40];

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

void CudaManager::gpu_pattern_check() {
    pattern_check<<<n_block_, thread_per_block_>>>(h[0], h[1], h[2], h[3], h[4]);
}

u32 CudaManager::get_result_index() {
    u32 offset;
    cudaMemcpyFromSymbol(&offset, result_index, sizeof(u32));

    if (offset != UINT32_MAX) {
        static u32 buf = UINT32_MAX;
        cudaMemcpyToSymbol(result_index, &buf, sizeof(u32));
    }

    return offset;
}
