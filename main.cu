#include <vector>
#include <fstream>
#include <iostream>
#include <ctime>
#include <cctype>
#include <cassert>
#include <csignal>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <memory>
#include <map>

extern "C" {
#include <sys/stat.h>
}

#include "gpgme_helper.hpp"
#include "key_test.hpp"

volatile sig_atomic_t cleanup_flag = 0;

void signal_handler(int sig) {
    cleanup_flag = 1;
}

struct Config {
    std::string pattern;
    std::string output;
    std::string algorithm;
    unsigned long time_offset;
    unsigned long thread_per_block;
};

int _main(const Config &conf) {
    signal(SIGINT, signal_handler); 
    signal(SIGTERM, signal_handler); 
    umask(0077);

    // Initialize GPGME
    NULLABLE_CALL(gpgme_check_version, nullptr);

    const int thread_per_block = conf.thread_per_block;
    const int time_offset = conf.time_offset;

    const int num_block = time_offset / thread_per_block;
    const int batch_size = num_block * thread_per_block;

    // Compile pattern
    load_patterns(conf.pattern);

    // CUDA allocation
    using cu_u32_ptr = std::unique_ptr<uint32_t, decltype(&cudaFree)>;
    auto cu_alloc = [](size_t size, bool managed) {
        void *ptr;
        auto err = managed ? cudaMallocManaged(&ptr, size) : cudaMalloc(&ptr, size);
        return err == cudaSuccess ? ptr : nullptr;
    };

    cu_u32_ptr retval((uint32_t*)cu_alloc(sizeof(uint32_t), true), cudaFree);
    *retval = UINT32_MAX;

    std::vector<cu_u32_ptr> h;
    for (int i = 0; i < 5; i++)
        h.push_back(cu_u32_ptr((uint32_t*)cu_alloc(batch_size * sizeof(uint32_t), false), cudaFree));

    if (std::find(h.begin(), h.end(), nullptr) != h.end()) {
        fprintf(stderr, "cudaMalloc() failed\n");
        return EXIT_FAILURE;
    }

    GPGHelper key_helper;
    unsigned long long count = 0ULL;
    uint32_t keytime;
    auto t0 = std::chrono::steady_clock::now();

    for (unsigned round = 0; round != UINT_MAX; round++) {
        if (cleanup_flag) {
            fprintf(stderr, "Signal caught! Let's exit...\n");
            break;
        }

        // generate key
        auto user_id = "KEY #" + std::to_string(round);
        key_helper.create_key(user_id, conf.algorithm);

        auto pubkey = key_helper.load_pubkey(user_id);
        auto n_chunk = load_key(pubkey);

        if (round) {
            auto prev_user_id = "KEY #" + std::to_string(round - 1);
            auto t1 = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsed = t1 - t0;

            count += batch_size;
            printf("Speed: %.4lf hashes / sec\n", count / elapsed.count());

            // retrieve previous result
            // put here so CPU/GPU runs together
            CU_CALL(cudaDeviceSynchronize);
            CU_CALL(cudaPeekAtLastError);

            if (*retval != UINT32_MAX) {
                auto buf = key_helper.load_privkey_full(prev_user_id);
                GPGHelper::change_keytime(buf, keytime - *retval);

                std::ofstream fout(conf.output, std::ofstream::binary);
                fout.write((const char*)buf.data(), buf.size());
                fout.close();

                printf("Result found!\n");
                printf("GPG key written to %s\n", conf.output.c_str());

                break;
            }

            key_helper.delete_key(prev_user_id);
        }

        // compute SHA-1 fingerprint
        keytime = time(NULL);
        for (size_t i = 0; i < n_chunk; i++)
            proc_chunk<<<num_block, thread_per_block>>>(
                    i, keytime, h[0].get(), h[1].get(), h[2].get(), h[3].get(), h[4].get());

        // search good pattern
        gpu_pattern_check<<<num_block, thread_per_block>>>(
                retval.get(), h[0].get(), h[1].get(), h[2].get(), h[3].get(), h[4].get());
    }

    CU_CALL(cudaDeviceSynchronize);
    CU_CALL(cudaPeekAtLastError);

    return 0;
}

void print_help(std::map<std::string, std::string> arg_map) {
    printf("  gpg-fingerprint-filter-gpu [OPTIONS] <pattern> <output>\n\n");
    printf("  <pattern>                   "
           "Key pattern to match, for example 'X{8}|(AB){4}'\n");
    printf("  <output>                    "
           "Save secret key to this path\n");
    printf("  -a, --algorithm <ALGO>      "
           "PGP key algorithm [default: %s]\n",
           arg_map["algorithm"].c_str());
    printf("  -t, --time-offset <N>       "
           "Max key timestamp offset [default: %s]\n",
           arg_map["time-offset"].c_str());
    printf("  -w, --thread-per-block <N>  "
           "CUDA thread number per block [default: %s]\n",
           arg_map["thread-per-block"].c_str());
    printf("  -h, --help\n");
}

int main(int argc, char* argv[]) {
    const std::string positional_args[] = { "pattern", "output" };
    const std::string named_args[][2] = {
        { "a", "algorithm" },
        { "t", "time-offset" },
        { "w", "thread-per-block" },
    };

    // default args
    std::map<std::string, std::string> arg_map_default;
    arg_map_default["algorithm"] = "default";
    arg_map_default["time-offset"] = "15552000";
    arg_map_default["thread-per-block"] = "512";

    auto arg_map = arg_map_default;
    std::string next_key = "";

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_help(arg_map_default);
            return 0;
        }

        if (next_key != "") {
            arg_map[next_key] = arg;
            next_key = "";
            continue;
        }

        for (auto &row: named_args) {
            if (arg == "-" + row[0] or arg == "--" + row[1]) {
                next_key = row[1];
                break;
            }
        }

        if (next_key == "") {
            bool parsed = false;

            for (auto &pos_arg: positional_args) {
                if (arg_map.count(pos_arg) == 0) {
                    arg_map[pos_arg] = arg;
                    parsed = true;
                    break;
                }
            }

            if (!parsed) {
                fprintf(stderr, "Unknown argument: %s\n\n", arg.c_str());
                print_help(arg_map_default);
                return EXIT_FAILURE;
            }
        }
    }

    Config config;
    try {
        config.pattern = arg_map.at("pattern");
        config.output = arg_map.at("output");
        config.algorithm = arg_map.at("algorithm");
        config.time_offset = std::stoul(arg_map.at("time-offset"));
        config.thread_per_block = std::stoul(arg_map.at("thread-per-block"));
    } catch (const std::out_of_range &e) {
        fprintf(stderr, "Missing argument!\n\n");
        print_help(arg_map_default);
        return EXIT_FAILURE;
    }

    try {
        return _main(config);
    } catch (const std::runtime_error &e) {
        // avoid annoying SIGABRT
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
