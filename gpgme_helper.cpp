#include "gpgme_helper.hpp"

#include <csignal>
#include <fstream>
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

GPGWorker::GPGWorker(size_t n_thread, const std::string &algo):
        algorithm(algo),
        key_stack(n_thread * 2) {
    const int channel_size = 8;  // a reasonable number

    DIE_ON_ERR(n_thread <= UINT16_MAX);
    for (size_t i = 0; i < n_thread; i++) {
        threads.emplace_back([this](uint16_t id) {
            sigset_t signal_mask;
            sigemptyset(&signal_mask);
            sigaddset(&signal_mask, SIGINT);
            sigaddset(&signal_mask, SIGTERM);
            DIE_ON_ERR(pthread_sigmask(SIG_BLOCK, &signal_mask, NULL) == 0);
            worker(id);
        }, i);
        channels.emplace_back(channel_size);
    }
}

GPGWorker::~GPGWorker() {
    if (!shutdown_flag)
        shutdown();
}

void GPGWorker::worker(uint16_t worker_id) {
    GPGHelper key_helper;
    uint16_t key_count = 0;
    uint32_t key_id_base = (uint32_t)worker_id << 16;
    char key_id_str[14];
    auto &my_channel = channels[worker_id];

    while (!shutdown_flag) {
        uint32_t key_id = key_id_base + key_count;
        sprintf(key_id_str, "KEY #%08X", key_id);

        key_helper.create_key(key_id_str, algorithm);
        auto pubkey = key_helper.load_pubkey(key_id_str);

        key_stack.push(KeyStorage(key_id, pubkey));
        key_count++;

        while (!my_channel.empty()) {
            auto result = my_channel.pop();
            key_id = std::get<0>(result);
            auto key_time = std::get<1>(result);
            auto save_to = std::get<2>(result);

            sprintf(key_id_str, "KEY #%08X", key_id);

            if (save_to != "") {
                auto buf = key_helper.load_privkey_full(key_id_str);
                GPGHelper::change_keytime(buf, key_time);

                std::ofstream fout(save_to, std::ofstream::binary);
                fout.write((const char*)buf.data(), buf.size());
                fout.close();

                printf("Result found!\n");
                printf("GPG key written to %s\n", save_to.c_str());
            }

            key_helper.delete_key(key_id_str);
        }
    }
}

KeyStorage GPGWorker::recv_key() {
    return key_stack.pop();
}

void GPGWorker::set_bad(uint32_t key_id) {
    set_good(key_id, 0, "");
}

void GPGWorker::set_good(uint32_t key_id, uint32_t key_time, std::string save_path) {
    uint16_t worker_id = key_id >> 16;
    channels[worker_id].push(std::make_tuple(key_id, key_time, save_path));
}

void GPGWorker::shutdown() {
    shutdown_flag = true;

    while (!key_stack.empty())
        key_stack.pop();

    for (auto &t: threads)
        t.join();
}
