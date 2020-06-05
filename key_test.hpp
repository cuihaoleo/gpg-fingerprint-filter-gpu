#ifndef _KEY_TEST_HPP_
#define _KEY_TEST_HPP_

#include <vector>
#include <cstdint>

#include <cuda_runtime_api.h>

#include "error_check.hpp"
#define CU_CALL(func, args...) error_wrapper<cudaError_t>(#func, (func)(args), cudaSuccess, cudaGetErrorString)

#define PATTERN_LIMIT 8

using u32 = std::uint32_t;
using u8 = std::uint8_t;

class CudaManager {
private:
    u32 *h[5] = {};
    u32 key_time0 = 0;

    int n_block_;
    int thread_per_block_;

    u32 load_key(const std::vector<u8> &pubkey);
    void gpu_proc_chunk(int n_chunk, u32 key_time0);

    void load_patterns(const std::string &input);
    void gpu_pattern_check();
    u32 get_result_index();

public:
    CudaManager(int n_block, int thread_per_block);

    CudaManager(const CudaManager&) = delete;
    CudaManager& operator= (const CudaManager&) = delete;

    ~CudaManager();

    void test_key(const std::vector<u8> &key, const std::string &pattern_string);
    u32 get_result_time();
};

#endif
