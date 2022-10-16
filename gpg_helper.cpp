#include "gpg_helper.hpp"

#include <csignal>
#include <fstream>

using sexp_ptr = std::unique_ptr<gcry_sexp, decltype(&gcry_sexp_release)>;
using mpi_ptr = std::unique_ptr<gcry_mpi, decltype(&gcry_free)>;

static std::vector<uint8_t> load_key_param(const sexp_ptr &key, char name) {
    char tmp[2] = { name, 0 };
    sexp_ptr n_sexp(gcry_sexp_find_token(key.get(), tmp, 0), gcry_sexp_release);

    if (n_sexp == nullptr)
        throw std::runtime_error(std::string("bad key parameter: ") + name);

    mpi_ptr mp(gcry_sexp_nth_mpi(n_sexp.get(), 1, GCRYMPI_FMT_USG), gcry_free);
    if (mp == nullptr)
        throw std::runtime_error(std::string("bad key parameter: ") + name);

    uint8_t *buf;
    size_t nbytes;
    GCRY_CALL(gcry_mpi_aprint, GCRYMPI_FMT_PGP, &buf, &nbytes, mp.get());
    std::vector<uint8_t> ret(buf, buf + nbytes);
    gcry_free(buf);

    return ret;
}

GPGKey::GPGKey(const std::string &algorithm) {
    std::string s_expr;
    std::vector<uint8_t> curve_oid;

    if (algorithm == "rsa") {
        s_expr = "(genkey(rsa(nbits 4:2048)))";
        pk_algo = PK_RSA;
    } else if (algorithm == "rsa2048") {
        s_expr = "(genkey(rsa(nbits 4:2048)))";
        pk_algo = PK_RSA;
    } else if (algorithm == "rsa3072") {
        s_expr = "(genkey(rsa(nbits 4:3072)))";
        pk_algo = PK_RSA;
    } else if (algorithm == "rsa4096") {
        s_expr = "(genkey(rsa(nbits 4:4096)))";
        pk_algo = PK_RSA;
    } else if (algorithm == "nistp256") {
        s_expr = "(genkey(ecc(curve nistp256)(flags nocomp)))";
        curve_oid = { 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        pk_algo = PK_ECDSA;
    } else if (algorithm == "nistp384") {
        s_expr = "(genkey(ecc(curve nistp384)(flags nocomp)))";
        curve_oid = { 5, 0x2B, 0x81, 0x04, 0x00, 0x22 };
        pk_algo = PK_ECDSA;
    } else if (algorithm == "nistp521") {
        s_expr = "(genkey(ecc(curve nistp521)(flags nocomp)))";
        curve_oid = { 5, 0x2B, 0x81, 0x04, 0x00, 0x23 };
        pk_algo = PK_ECDSA;
    } else if (algorithm == "ed25519") {
        s_expr = "(genkey(ecc(curve Ed25519)(flags eddsa comp)))";
        curve_oid = { 9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };
        pk_algo = PK_EDDSA;
    } else if (algorithm == "cv25519") {
        s_expr = "(genkey(ecc(curve Curve25519)(flags djb-tweak comp)))";
        curve_oid = { 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
        pk_algo = PK_ECDH;
    } else {
        throw std::runtime_error("unsupported algorithm: " + algorithm);
    }

    gcry_sexp_t tmp;

    GCRY_CALL(gcry_sexp_build, &tmp, NULL, s_expr.c_str());
    sexp_ptr genkey_param(tmp, gcry_sexp_release);

    GCRY_CALL(gcry_pk_genkey, &tmp, genkey_param.get());
    sexp_ptr keypair(tmp, gcry_sexp_release);

    sexp_ptr public_key(gcry_sexp_find_token(keypair.get(), "public-key", 0), gcry_sexp_release);
    sexp_ptr private_key(gcry_sexp_find_token(keypair.get(), "private-key", 0), gcry_sexp_release);

    std::string private_param_names;
    std::string public_param_names;

    // DSA: pqgy / +x, but I don't want to implement
    if (pk_algo == PK_RSA) {
        public_param_names = "ne";
        private_param_names = "dpqu";
    } else if (pk_algo == PK_ECDSA || pk_algo == PK_EDDSA || pk_algo == PK_ECDH) {
        public_params.push_back(curve_oid);
        public_param_names = "q";
        private_param_names = "d";
    }

    for (auto k: public_param_names)
        public_params.emplace_back(load_key_param(public_key, k));

    // secret sauce
    if (pk_algo == PK_ECDH)
        public_params.push_back({0x03, 0x01, 0x08, 0x07});

    for (auto k: private_param_names)
        private_params.emplace_back(load_key_param(private_key, k));

    creation_time = 0;
}

std::vector<uint8_t> GPGKey::load_fpr_hash_packet() const {
    std::vector<uint8_t> buf;
    uint16_t octet_count;

    buf.push_back(0x99);

    // octet_count
    octet_count = 6;
    for (auto &item: public_params)
        octet_count += item.size();

    buf.reserve(octet_count + 3);
    buf.push_back(octet_count >> 8);
    buf.push_back(octet_count & 0xFF);

    // version
    buf.push_back(0x04);

    // key creation time
    buf.push_back(creation_time >> 24);
    buf.push_back((creation_time >> 16) & 0xFF);
    buf.push_back((creation_time >> 8) & 0xFF);
    buf.push_back(creation_time & 0xFF);

    // algorithm
    buf.push_back(pk_algo);

    for (auto &item: public_params)
        buf.insert(buf.end(), item.begin(), item.end());

    return buf;
}

std::vector<uint8_t> GPGKey::load_seckey_packet() const {
    std::vector<uint8_t> buf;
    uint32_t octet_count;

    octet_count = 9;
    for (auto &params: { public_params, private_params })
        for (auto &item: params)
            octet_count += item.size();

    // header & octet_count
    if (octet_count < 192) {
        buf.reserve(octet_count + 2);
        buf.push_back(0x94);
        buf.push_back(octet_count & 0xFF);
    } else if (octet_count < 8384) {
        buf.reserve(octet_count + 3);
        buf.push_back(0x95);
        buf.push_back(octet_count >> 8);
        buf.push_back(octet_count & 0xFF);
    } else {
        buf.reserve(octet_count + 5);
        buf.push_back(0x96);
        buf.push_back(octet_count >> 24);
        buf.push_back((octet_count >> 16) & 0xFF);
        buf.push_back((octet_count >> 8) & 0xFF);
        buf.push_back(octet_count & 0xFF);
    }

    // version
    buf.push_back(0x04);

    // key creation time
    buf.push_back(creation_time >> 24);
    buf.push_back((creation_time >> 16) & 0xFF);
    buf.push_back((creation_time >> 8) & 0xFF);
    buf.push_back(creation_time & 0xFF);

    // algorithm
    buf.push_back(pk_algo);

    // public params
    for (auto &item: public_params)
        buf.insert(buf.end(), item.begin(), item.end());

    // string-to-key usage
    buf.push_back(0);

    // private params
    uint16_t csum = 0;
    for (auto &item: private_params)
        for (auto n: item) {
            csum += n;
            buf.push_back(n);
        }

    // checksum
    buf.push_back(csum >> 8);
    buf.push_back(csum & 0xFF);

    return buf;
}

void GPGKey::set_creation_time(uint32_t timestamp) {
    creation_time = timestamp;
}

GPGWorker::GPGWorker(size_t n_thread, const std::string &algo):
        algorithm(algo),
        key_stack(n_thread * 2) {
    // initialize gcrypt
    NULLABLE_CALL(gcry_check_version, GCRYPT_VERSION);
    GCRY_CALL(gcry_control, GCRYCTL_DISABLE_SECMEM, 0);
    GCRY_CALL(gcry_control, GCRYCTL_INITIALIZATION_FINISHED, 0);

    for (size_t i = 0; i < n_thread; i++) {
        threads.emplace_back([this]() {
            sigset_t signal_mask;
            sigemptyset(&signal_mask);
            sigaddset(&signal_mask, SIGINT);
            sigaddset(&signal_mask, SIGTERM);
            DIE_ON_ERR(pthread_sigmask(SIG_BLOCK, &signal_mask, NULL) == 0);
            worker();
        });
    }
}

GPGWorker::~GPGWorker() {
    if (!shutdown_flag)
        shutdown();
}

void GPGWorker::worker() {
    while (!shutdown_flag)
        key_stack.emplace(algorithm);
}

GPGKey GPGWorker::recv_key() {
    return key_stack.pop();
}

void GPGWorker::shutdown() {
    shutdown_flag = true;

    while (!key_stack.empty())
        key_stack.pop();

    for (auto &t: threads)
        t.join();
}
