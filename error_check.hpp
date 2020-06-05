#ifndef _ERROR_CHECK_HPP_
#define _ERROR_CHECK_HPP_

#include <stdexcept>

template<typename ErrorT> inline void error_wrapper(
        const char *func,
        ErrorT code,
        ErrorT good_code,
        const char * (*strerror)(ErrorT) = nullptr) {
    if (code != good_code) {
        auto what = func + std::string(" failed");
        if (strerror)
            what += std::string(": ") + strerror(code);
        throw std::runtime_error(what);
    }
}

#define NULLABLE_CALL(func, args...) error_wrapper<bool>(#func, ((func)(args)) != nullptr, true)
#define DIE_ON_ERR(cond) error_wrapper<bool>("assertion "#cond, cond, true)

#endif
