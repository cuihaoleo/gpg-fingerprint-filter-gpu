#ifndef _GPG_HELPER_HPP_
#define _GPG_HELPER_HPP_

#include <vector>
#include <thread>

#include <cstdint>

#include <gcrypt.h>

#include "safe_stack.hpp"
#include "error_check.hpp"
#define GCRY_CALL(func, args...) error_wrapper<gcry_error_t>(#func, (func)(args), GPG_ERR_NO_ERROR, gcry_strerror)

class GPGKey {
private:
    enum openpgp_pk_algos {
        PK_RSA = 1,
        PK_ECDH = 18,
        PK_ECDSA = 19,
        PK_EDDSA = 22,
    };

    openpgp_pk_algos pk_algo;
    uint32_t creation_time;
    std::vector<std::vector<uint8_t>> private_params;
    std::vector<std::vector<uint8_t>> public_params;
public:
    explicit GPGKey(const std::string &algorithm);

    GPGKey(const GPGKey&) = delete;
    GPGKey& operator=(const GPGKey&) = delete;
    GPGKey(GPGKey&&) = default;
    GPGKey& operator=(GPGKey&&) = default;

    std::vector<uint8_t> load_fpr_hash_packet() const;
    std::vector<uint8_t> load_seckey_packet() const;
    void set_creation_time(uint32_t timestamp);
};

class GPGWorker {
private:
    bool shutdown_flag = false;
    std::string algorithm;
    std::deque<std::thread> threads;
    SafeStack<GPGKey> key_stack;

    void worker();

public:
    explicit GPGWorker(size_t n_thread, const std::string &algo);

    GPGWorker(const GPGWorker&) = delete;
    GPGWorker& operator= (const GPGWorker&) = delete;

    ~GPGWorker();

    GPGKey recv_key();
    void shutdown();
};

#endif
