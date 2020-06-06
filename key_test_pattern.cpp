#include "key_test.hpp"

#include <map>
#include <memory>
#include <sstream>

#include <nvrtc.h>
#define NVRTC_CALL(func, args...) error_wrapper<nvrtcResult>(#func, (func)(args), NVRTC_SUCCESS, nvrtcGetErrorString)

static std::string compile_single_pattern(const std::string &pattern) {
    std::vector<int> tmp_out;
    std::map<char, int> symbol_map;

    int bra = -1, ket = -1;
    const char *p;

    for (char i = '0'; i <= '9'; i++)
        symbol_map[i] = (i - '0') - 100;

    for (char i = 'A'; i <= 'F'; i++)
        symbol_map[i] = (i - 'A' + 10) - 100;

    for (p = pattern.c_str(); *p; p++) {
        switch (*p) {
            case '(': {
                if (bra == -1)
                    bra = tmp_out.size();
                else
                    return "";

                break;
            };
            case ')': {
                if (bra != -1)
                    ket = tmp_out.size();
                else
                    return "";

                break;
            }
            case '{': {
                unsigned long num = strtoul(++p, (char**)&p, 10);

                if (*p != '}' || num == 0)
                    return "";

                int i0, i1;
                if (ket == -1) {
                    i0 = tmp_out.size() - 1;
                    i1 = tmp_out.size();
                } else {
                    i0 = bra;
                    i1 = ket;
                    bra = ket = -1;
                }

                for (unsigned long i = 0; i < num - 1; i++)
                    for (int j = i0; j < i1; j++)
                        tmp_out.push_back(tmp_out[j]);

                break;
            }
            default: {
                if (isdigit(*p) || isalpha(*p)) {
                    char symbol = toupper(*p);

                    if (symbol_map.count(symbol) == 0)
                        symbol_map[symbol] = tmp_out.size();

                    tmp_out.push_back(symbol_map[symbol]);
                } else
                    return "";

                if (ket != -1)
                    bra = ket = -1;
            }
        };
    }

    int offset = 40 - tmp_out.size();
    if ((offset < 0) || (bra != -1 && ket == -1))
        return "";

    std::stringstream ss;
    for (auto i = 0u; i < tmp_out.size(); i++) {
        auto item = tmp_out[i];

        if (item != static_cast<int>(i)) {
            ss << "w[" << i + offset << "] == ";

            if (item < 0)
                ss << tmp_out[i] + 100;
            else
                ss << "w[" << item + offset << "]";

            ss << " && ";
        }
    }

    std::string ret = ss.str();

    if (ret == "")
        return "1";
    else
        return ret.substr(0, ret.size() - 4);
}

static std::string compile_patterns(const std::string &input) {
    std::stringstream ss;
    std::string::size_type pos;
    std::string buffer = input + "|";

    ss << "\
#define __ASSEMBLER__\n\
#define __extension__\n\
#include <stdint.h>\n\
typedef uint32_t u32; \n\
extern \"C\" __global__ \n\
void pattern_check(u32 *result";
    for (int i = 0; i < 5; i++)
        ss << ", const u32* __restrict__ h" << i;

    ss << ") {\n\
  size_t index = blockIdx.x * blockDim.x + threadIdx.x; \n\
  uint32_t tmp; \n\
  uint8_t w[40]; \n";

    for (int i = 0; i < 5; i++) {
        ss << "  tmp = h" << i << "[index];\n";
        for (int j = 0; j < 7; j++) {
            ss << "  w[" << i * 8 + j << "] = "
               << "(tmp >> " << (7 - j) * 4 << ") & 0x0F;\n";
        }
        ss << "  w[" << i * 8 + 7 << "] = tmp & 0x0F;\n";
    }

    ss << "  if (";

    while ((pos = buffer.find("|")) != std::string::npos) {
        auto pattern = buffer.substr(0, pos);
        auto code = compile_single_pattern(pattern);

        if (code == "")
            return "";

        ss << "(" << code << ") || ";
        buffer.erase(0, pos + 1);
    }

    ss.seekp(-4, std::ios_base::end);
    ss << ") *result = index;\n}\n";

    return ss.str();
}

void CudaManager::load_patterns(const std::string &input) {
    auto cuda_src = compile_patterns(input);

    nvrtcProgram prog;
    NVRTC_CALL(nvrtcCreateProgram, &prog, cuda_src.c_str(), NULL, 0, NULL, NULL);

    int dev_major, dev_minor;
    CU_CALL(cuDeviceGetAttribute, &dev_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, cu_device);
    CU_CALL(cuDeviceGetAttribute, &dev_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, cu_device);

    std::string arch = "-arch=compute_";
    arch += std::to_string(dev_major);
    arch += std::to_string(dev_minor);

    try {
        const char *opts[] = { arch.c_str() };
        NVRTC_CALL(nvrtcCompileProgram, prog, 1, opts);
    } catch (const std::runtime_error &e) {
        size_t log_size;
        NVRTC_CALL(nvrtcGetProgramLogSize, prog, &log_size);
        auto log = std::vector<char>(log_size);
        NVRTC_CALL(nvrtcGetProgramLog, prog, log.data());
        fprintf(stderr, "nvrtcCompileProgram failed:\n%s\n", log.data());
        throw;
    }

    size_t ptx_size;
    nvrtcGetPTXSize(prog, &ptx_size);

    auto ptx = std::vector<char>(ptx_size);
    NVRTC_CALL(nvrtcGetPTX, prog, ptx.data());

    NVRTC_CALL(nvrtcDestroyProgram, &prog);

    CU_CALL(cuModuleLoadData, &cu_module, ptx.data());
    CU_CALL(cuModuleGetFunction, &cu_kernel, cu_module, "pattern_check");

    CU_CALL(cuMemAlloc, &cu_result, sizeof(uint32_t));
    CU_CALL(cuMemsetD32, cu_result, UINT32_MAX, 1);
};

void CudaManager::gpu_pattern_check() {
    void *args[] = {&cu_result, h + 0, h + 1, h + 2, h + 3, h + 4};
    CU_CALL(cuLaunchKernel,
            cu_kernel,
            n_block_, 1, 1,
            thread_per_block_, 1, 1,
            0, 0, args, 0);
}
