#include "gpgme_helper.hpp"

#include <experimental/filesystem>
using namespace std::experimental;

GPGHelper::GPGHelper() {
    NULLABLE_CALL(mkdtemp, tmpdir);
    GPGME_CALL(gpgme_new, &ctx);
    GPGME_CALL(gpgme_ctx_set_engine_info, ctx, GPGME_PROTOCOL_OpenPGP, NULL, tmpdir);
}

GPGHelper::~GPGHelper() {
    gpgme_release(ctx);
    filesystem::remove_all(tmpdir);
}

void GPGHelper::create_key(std::string user_id, std::string algo) {
    GPGME_CALL(
        gpgme_op_createkey,
        ctx,
        user_id.c_str(),
        algo.c_str(),
        0,
        0,
        NULL,
        GPGME_CREATE_CERT | GPGME_CREATE_NOPASSWD
    );
}

void GPGHelper::delete_key(std::string user_id) {
    gpgme_error_t err = GPG_ERR_NO_ERROR;
    GPGME_CALL(gpgme_op_keylist_start, ctx, user_id.c_str(), 0);
    std::vector<std::string> fingerprint_list;
    gpgme_key_t key; 

    while ((err = gpgme_op_keylist_next(ctx, &key)) == GPG_ERR_NO_ERROR) {
        fingerprint_list.push_back(key->fpr);
        gpgme_key_unref(key);
    }

    if (gpg_err_code(err) != GPG_ERR_EOF)
        throw std::runtime_error("gpgme_op_keylist failed");

    for (const auto &fpr: fingerprint_list) {
        GPGME_CALL(gpgme_get_key, ctx, fpr.c_str(), &key, 0);
        GPGME_CALL(gpgme_op_delete_ext, ctx, key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
        gpgme_key_unref(key);
    }
}

std::vector<uint8_t> GPGHelper::load_pubkey(std::string user_id) {
    gpgme_data_t data;
    GPGME_CALL(gpgme_data_new, &data);

    GPGME_CALL(gpgme_op_export, ctx, user_id.c_str(), GPGME_EXPORT_MODE_MINIMAL, data);

    auto file_size = gpgme_data_seek(data, 0, SEEK_END);
    DIE_ON_ERR(file_size >= 10);

    auto offset = gpgme_data_seek(data, 0, SEEK_SET);
    DIE_ON_ERR(offset == 0);

    std::vector<uint8_t> buf;
    buf.resize(file_size);

    auto nread = gpgme_data_read(data, buf.data(), file_size);
    DIE_ON_ERR(nread == file_size);

    gpgme_data_release(data);

    switch (buf[0]) {
        case 0x98: {
            buf[0] = 0x99;
            buf.insert(buf.begin() + 1, 0x00);
        }
        case 0x99: {
            size_t pubkey_length = buf[1] * 256 + buf[2] + 3;
            buf.resize(pubkey_length);
            break;
        }
        default:
            throw std::runtime_error("bad key payload");
    }

    return buf;
}

std::vector<uint8_t> GPGHelper::load_privkey_full(std::string user_id) {
    gpgme_data_t data;
    GPGME_CALL(gpgme_data_new, &data);

    GPGME_CALL(gpgme_op_export, ctx, user_id.c_str(), GPGME_EXPORT_MODE_MINIMAL | GPGME_EXPORT_MODE_SECRET, data);

    auto file_size = gpgme_data_seek(data, 0, SEEK_END);
    gpgme_data_seek(data, 0, SEEK_SET);

    std::vector<uint8_t> buf;
    buf.resize(file_size);
    auto nread = gpgme_data_read(data, buf.data(), file_size);
    DIE_ON_ERR(nread == file_size);

    gpgme_data_release(data);

    return buf;
}

void GPGHelper::change_keytime(std::vector<uint8_t> &key, uint32_t key_time) {
    std::vector<uint8_t>::iterator it;
    DIE_ON_ERR(key.size() > 10);

    switch (key[0]) {
        case 0x94: it = key.begin() + 3; break;
        case 0x95: it = key.begin() + 4; break;
        default: throw std::runtime_error("bad key payload");
    }

    *(it++) = (key_time >> 24) & 0xFF;
    *(it++) = (key_time >> 16) & 0xFF;
    *(it++) = (key_time >> 8) & 0xFF;
    *(it++) = key_time & 0xFF;
}
