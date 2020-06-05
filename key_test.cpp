#include "key_test.hpp"

CudaManager::CudaManager(int n_block, int thread_per_block):
        n_block_(n_block), thread_per_block_(thread_per_block) {
    int batch_size = n_block * thread_per_block;
    for (auto &ptr: h)
        CU_CALL(cudaMalloc, (void**)&ptr, batch_size * sizeof(u32));
}

CudaManager::~CudaManager() {
    CU_CALL(cudaDeviceSynchronize);
    CU_CALL(cudaPeekAtLastError);

    for (auto &ptr: h)
        cudaFree(ptr);
}

void CudaManager::test_key(const std::vector<u8> &key, const std::string &pattern_string) {
    static std::string pattern_string_ = "";

    if (pattern_string != pattern_string_)
        load_patterns(pattern_string_ = pattern_string);

    auto n_chunk = load_key(key);
    key_time0 = time(NULL);

    gpu_proc_chunk(n_chunk, key_time0);
    gpu_pattern_check();
}

u32 CudaManager::get_result_time() {
    u32 offset = get_result_index();
    CU_CALL(cudaPeekAtLastError);

    if (offset == UINT32_MAX)
        return UINT32_MAX;
    else
        return key_time0 - get_result_index();
}
