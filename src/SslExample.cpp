#include "SslExample.h"

#include <string>
#include <system_error>
#include <tuple>

namespace nds {

struct SslAesConfig aesSimpleConfig {
    .type = EVP_aes_256_cbc(), .impl = NULL,
    .key = (unsigned char*)"01234567890123456789012345678901",
    .iv = (unsigned char*)"someIV"
};

namespace detail {

const char* SslErrorCategory::name() const noexcept { return "SslError"; }

std::string SslErrorCategory::message(int ev) const {
    static std::string messages[] = {"no error",
                                     "cannot create context",
                                     "cannot init enc context",
                                     "cannot update enc context",
                                     "cannot finish enc context",
                                     "cannot init dec context",
                                     "cannot update dec context",
                                     "cannot finish dec context"};

    if (ev < sizeof(messages))
        return messages[ev];
    else
        return "unknow error";
}

std::error_condition SslErrorCategory::default_error_condition(
    int error) const noexcept {
    SslErrorConditional condition;
    switch (static_cast<SslError>(error)) {
        case SslError::Success:
        case SslError::ContextCreate:
        case SslError::EncInit:
        case SslError::EncUpdate:
        case SslError::EncFinal:
        case SslError::DecInit:
        case SslError::DecUpdate:
        case SslError::DecFinal:
            condition = SslErrorConditional::ERROR_CODE;
        default:
            condition = SslErrorConditional::UNKNOWN_ERROR;
    }

    return std::error_condition(condition);
}

bool SslErrorCategory::equivalent(const std::error_code& error_code,
                                  int error_value) const noexcept {
    return *this == error_code.category() &&
           static_cast<int>(
               default_error_condition(error_code.value()).value()) ==
               error_value;
}

bool SslErrorCategory::equivalent(
    int error, const std::error_condition& condition) const noexcept {
    return default_error_condition(error) == condition;
}

}  // namespace detail

SslExample::SslExample() : _ctx(nullptr) {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    // OPENSSL_config(NULL);
    OPENSSL_no_config();
}

SslExample::SslExample(SslExample&& other) : _ctx(nullptr) {
    _ctx = other._ctx;
    other._ctx = nullptr;
}

SslExample& SslExample::operator=(SslExample&& other) {
    if (_ctx != nullptr) cleanup();

    _ctx = other._ctx;
    other._ctx = nullptr;

    return *this;
}

SslExample::~SslExample() { cleanup(); }

void SslExample::cleanup() { EVP_CIPHER_CTX_free(_ctx); }

}  // namespace nds
