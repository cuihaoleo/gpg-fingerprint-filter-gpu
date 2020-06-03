#ifndef _GPGME_HELPER_HPP_
#define _GPGME_HELPER_HPP_

#include <cstdint>
#include <vector>

#include <gpgme.h>
#include "error_check.hpp"

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

#endif
