#ifndef _GPGME_HELPER_HPP_
#define _GPGME_HELPER_HPP_

#include <cstdint>
#include <utility>
#include <vector>
#include <thread>

#include <gpgme.h>
#include "error_check.hpp"
#include "safe_stack.hpp"

#define GPGME_CALL(func, args...) error_wrapper<gpgme_error_t>(#func, (func)(args), GPG_ERR_NO_ERROR, gpgme_strerror)

class GPGHelper {
private:
    gpgme_ctx_t ctx;
    char tmpdir[22] = "/tmp/.libgpgme.XXXXXX";

public:
    static void change_keytime(std::vector<uint8_t> &key, uint32_t keytime);

    GPGHelper();
    ~GPGHelper();

    void create_key(std::string user_id, std::string algo);
    void delete_key(std::string user_id);
    std::vector<uint8_t> load_pubkey(std::string user_id);
    std::vector<uint8_t> load_privkey_full(std::string user_id);
};

using KeyBuffer = std::vector<uint8_t>;
struct KeyStorage {
    uint32_t id;
    KeyBuffer buffer;
    KeyStorage(uint32_t id, const KeyBuffer &buf): id(id), buffer(buf) {};
};

class GPGWorker {
private:
    bool shutdown_flag = false;
    std::string algorithm;
    std::deque<std::thread> threads;
    SafeStack<KeyStorage> key_stack;

    using Result = std::tuple<uint32_t, uint32_t, std::string>;
    std::deque<SafeStack<Result>> channels;

    void worker(uint16_t worker_id);

public:
    GPGWorker(size_t n_thread, const std::string &algo);
    ~GPGWorker();

    KeyStorage recv_key();
    void set_bad(uint32_t key_id);
    void set_good(uint32_t key_id, uint32_t key_time, std::string save_path);
    void shutdown();
};

#endif
