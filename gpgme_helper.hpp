#ifndef _GPGME_HELPER_HPP_
#define _GPGME_HELPER_HPP_

#include <vector>
#include <thread>
#include <utility>
#include <experimental/filesystem>

#include <cstdint>

#include <gpgme.h>

#include "safe_stack.hpp"
#include "error_check.hpp"
#define GPGME_CALL(func, args...) error_wrapper<gpgme_error_t>(#func, (func)(args), GPG_ERR_NO_ERROR, gpgme_strerror)

namespace filesystem = std::experimental::filesystem;

class GPGHelper {
private:
    gpgme_ctx_t ctx;
    filesystem::path tmpdir;
    void reset_tmpdir();

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
