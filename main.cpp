#include <fstream>
#include <iostream>
#include <map>

#include <csignal>
#include <cstring>
#include <cstdint>

extern "C" {
#include <sys/stat.h>
#include <sys/sysinfo.h>
}

#include "key_test.hpp"
#include "gpg_helper.hpp"

volatile sig_atomic_t cleanup_flag = 0;

void signal_handler(int sig) {
    (void)sig;
    cleanup_flag = 1;
}

struct Config {
    std::string pattern;
    std::string output;
    std::string algorithm;
    unsigned long time_offset;
    unsigned long thread_per_block;
    unsigned long gpg_thread;
    unsigned long base_time;
    bool batch_mode;
};

int _main(const Config &conf) {
    signal(SIGINT, signal_handler); 
    signal(SIGTERM, signal_handler); 
    umask(0077);

    const int thread_per_block = conf.thread_per_block;
    const int time_offset = conf.time_offset;

    const int num_block = time_offset / thread_per_block;

    GPGWorker key_worker(conf.gpg_thread, conf.algorithm);
    CudaManager manager(num_block, thread_per_block, conf.base_time);
    manager.load_patterns(conf.pattern);

    unsigned long long count = 0ULL;
    auto t0 = std::chrono::steady_clock::now();

    while (true) {
        if (cleanup_flag) {
            fprintf(stderr, "\nSignal caught! Let's exit...\n");
            break;
        }

        // generate key
        auto key = key_worker.recv_key();
        manager.test_key(key.load_fpr_hash_packet());
        u32 result_time = manager.get_result_time();

        if (result_time != UINT32_MAX) {
            key.set_creation_time(result_time);
            auto packet = key.load_seckey_packet();
            // add random to avoid collision
            auto filename = conf.output + "/" + std::to_string(result_time) +
                            "." + std::to_string(rand()) + ".gpg";
            std::ofstream fout(filename, std::ios::binary);
            fout.write((char*)packet.data(), packet.size());

            // user-id packet
            fout.write("\xb4\x06NONAME", 8);

            puts("\nResult found!");
            printf("GPG key written to %s\n", filename.c_str());

            if (!conf.batch_mode)
                break;
        }

        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = t1 - t0;
        count += num_block * thread_per_block;
        printf("\rSpeed: %.4lf hashes / sec", count / elapsed.count());
    }

    key_worker.shutdown();
    return 0;
}

void print_help(std::map<std::string, std::string> arg_map) {
    printf("  gpg-fingerprint-filter-gpu [OPTIONS] <pattern> <output>\n\n");
    printf("  <pattern>                   "
           "Fingerprint pattern to match, for example 'X{8}|(AB){4}'\n");
    printf("  <output>                    "
           "Save the secret key(s) to this folder\n");
    printf("  -a, --algorithm <ALGO>      "
           "PGP key algorithm [default: %s]\n",
           arg_map["algorithm"].c_str());
    printf("  -b, --base-time <N>         "
           "Base key timestamp in UNIX epoch [default: %s]\n",
           "now");
    printf("  -t, --time-offset <N>       "
           "Max key timestamp offset in seconds [default: %s]\n",
           arg_map["time-offset"].c_str());
    printf("  -w, --thread-per-block <N>  "
           "Number of CUDA threads per block [default: %s]\n",
           arg_map["thread-per-block"].c_str());
    printf("  -j, --gpg-thread <N>        "
           "Number of threads to generate keys [default: %s]\n",
           "# of CPUs");
    printf("  -m, --batch-mode <Y/N>      "
           "Continue to generate keys even if a match is found [default: %s]\n",
           "N");
    printf("  -h, --help\n");
}

int main(int argc, char* argv[]) {
    const std::string positional_args[] = { "pattern", "output" };
    const std::string named_args[][2] = {
        { "a", "algorithm" },
        { "b", "base-time" },
        { "t", "time-offset" },
        { "w", "thread-per-block" },
        { "j", "gpg-thread" },
        { "m", "batch-mode" },
    };

    // default args
    std::map<std::string, std::string> arg_map_default;
    arg_map_default["algorithm"] = "rsa";
    arg_map_default["base-time"] = std::to_string(time(NULL));
    arg_map_default["time-offset"] = "15552000";
    arg_map_default["thread-per-block"] = "512";
    arg_map_default["gpg-thread"] = std::to_string(std::max(get_nprocs(), 1));
    arg_map_default["batch-mode"] = "N";

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

        for (auto &row: named_args)
            if (arg == "-" + row[0] || arg == "--" + row[1]) {
                next_key = row[1];
                break;
            }

        if (next_key == "") {
            bool parsed = false;

            for (auto &pos_arg: positional_args)
                if (arg_map.count(pos_arg) == 0) {
                    arg_map[pos_arg] = arg;
                    parsed = true;
                    break;
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
        config.base_time = std::stoul(arg_map.at("base-time"));
        config.time_offset = std::stoul(arg_map.at("time-offset"));
        config.thread_per_block = std::stoul(arg_map.at("thread-per-block"));
        config.gpg_thread = std::stoul(arg_map.at("gpg-thread"));
        config.batch_mode = arg_map.at("batch-mode")[0] == 'Y' ||
                            arg_map.at("batch-mode")[0] == 'y';
    } catch (const std::out_of_range &e) {
        fprintf(stderr, "Missing argument!\n\n");
        print_help(arg_map_default);
        return EXIT_FAILURE;
    }

    try {
        mkdir(config.output.c_str(), 0700);
        return _main(config);
    } catch (const std::runtime_error &e) {
        // avoid annoying SIGABRT
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
