#include "key_test.hpp"

const char *cuGetErrorName_wrapper(CUresult err) {
    const char *msg;
    cuGetErrorName(err, &msg);
    return msg;
}

CudaManager::CudaManager(int n_block, int thread_per_block):
        n_block_(n_block), thread_per_block_(thread_per_block) {
    int batch_size = n_block * thread_per_block;

    CU_CALL(cuInit, 0);
    CU_CALL(cuDeviceGet, &cu_device, 0);
    CU_CALL(cuDevicePrimaryCtxRetain, &cu_context, cu_device);

    for (auto &ptr: h)
        CUDA_CALL(cudaMalloc, (void**)&ptr, batch_size * sizeof(u32));
}

CudaManager::~CudaManager() {
    if (cu_module != nullptr)
        cuModuleUnload(cu_module);

    if (cu_result)
        cuMemFree(cu_result);

    CUDA_CALL(cudaDeviceSynchronize);
    CUDA_CALL(cudaPeekAtLastError);

    for (auto &ptr: h)
        cudaFree(ptr);

    if (cu_context != nullptr)
        CU_CALL(cuDevicePrimaryCtxRelease, cu_device);
}

void CudaManager::test_key(const std::vector<u8> &key) {
    auto n_chunk = load_key(key);
    key_time0 = time(NULL);

    gpu_proc_chunk(n_chunk, key_time0);
    gpu_pattern_check();
}

u32 CudaManager::get_result_time() const {
    u32 offset;
    CU_CALL(cuMemcpyDtoH, &offset, cu_result, sizeof(uint32_t));

    if (offset != UINT32_MAX)
        CU_CALL(cuMemsetD32, cu_result, UINT32_MAX, 1);

    return offset == UINT32_MAX ? UINT32_MAX : key_time0 - offset;
}
