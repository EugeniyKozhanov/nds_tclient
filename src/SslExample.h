#pragma once

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <string>
#include <system_error>
#include <tuple>
#include <utility>

namespace nds {

namespace detail {

enum class SslError {
    Success = 0,
    ContextCreate,
    EncInit,
    EncUpdate,
    EncFinal,
    DecInit,
    DecUpdate,
    DecFinal
};

enum class SslErrorConditional {
    ERROR_CODE = 0,
    UNKNOWN_ERROR
};

class SslErrorCategory : public std::error_category {
   public:
    SslErrorCategory() noexcept {};
    virtual const char* name() const noexcept override;
    virtual std::string message(int ev) const override;

    std::error_condition default_error_condition(int err_value) const noexcept override;
    bool equivalent(const std::error_code& err_code, int err_value) const noexcept override;
    bool equivalent(int err_value, const std::error_condition& err_cond) const noexcept override;

   private:
    SslErrorCategory(const SslErrorCategory&) = delete;
    SslErrorCategory(SslErrorCategory&&) = delete;
    SslErrorCategory& operator=(const SslErrorCategory&) = delete;
    SslErrorCategory& operator=(SslErrorCategory&&) = delete;

} const SslErrorCategory;

inline std::error_code make_error_code(nds::detail::SslError error) {
    return std::error_code(static_cast<int>(error), nds::detail::SslErrorCategory);
}

inline std::error_condition make_error_condition(nds::detail::SslErrorConditional condition) noexcept {
    return std::error_condition(static_cast<int>(condition), nds::detail::SslErrorCategory);
}

}  // namespace detail

struct SslAesConfig {
    const EVP_CIPHER* type;
    ENGINE* impl;
    unsigned char* key;
    unsigned char* iv;
};
extern struct SslAesConfig aesSimpleConfig;

class SslExample {
   public:
    SslExample();

    SslExample(const SslExample&) = delete;
    SslExample& operator=(const SslExample&) = delete;

    SslExample(SslExample&& other);
    SslExample& operator=(SslExample&& other);

    ~SslExample();

    std::pair<std::error_code, std::string> decrypt(const std::string& text) {
        std::string decr;
        std::error_code error = process<decltype(EVP_DecryptInit_ex), decltype(EVP_DecryptUpdate), decltype(EVP_DecryptFinal_ex)>(
            EVP_DecryptInit_ex,
            EVP_DecryptUpdate,
            EVP_DecryptFinal_ex,
            text,
            decr,
            static_cast<int>(detail::SslError::DecInit));

        return std::make_pair(error, decr);
    }

    std::pair<std::error_code, std::string> encrypt(const std::string& text) {
        std::string encr;
        std::error_code error = process<decltype(EVP_EncryptInit_ex), decltype(EVP_EncryptUpdate), decltype(EVP_EncryptFinal_ex)>(
            EVP_EncryptInit_ex,
            EVP_EncryptUpdate,
            EVP_EncryptFinal_ex,
            text,
            encr,
            static_cast<int>(detail::SslError::EncInit));

        return std::make_pair(error, encr);
    }

   private:
    EVP_CIPHER_CTX* _ctx;

    template <class F1, class F2, class F3>
    std::error_code process(F1 init_f, F2 update_f, F3 final_f, const std::string& orig_text, std::string& new_text, int error_offset) {
        std::error_code ret = detail::SslError::Success;

        if (!(_ctx = EVP_CIPHER_CTX_new())) {
            ret = detail::SslError::ContextCreate;
            return ret;
        }

        auto [chipher, eingeine, key, iv] = aesSimpleConfig;
        if (1 != std::apply(init_f, std::make_tuple(_ctx, chipher, eingeine, key, iv))) {
            ret = static_cast<detail::SslError>(error_offset);
            return ret;
        }

        // TODO:
        unsigned char buffer[128];
        int buffer_len = 0;
        int current_len;

        if (1 != std::apply(update_f, std::make_tuple(_ctx, buffer, &current_len, (const unsigned char*)(orig_text.c_str()), orig_text.length()))) {
            ret = static_cast<detail::SslError>(error_offset + 1);
            return ret;
        }
        buffer_len = current_len;

        if (1 != std::apply(final_f, std::make_tuple(_ctx, buffer + current_len, &current_len))) {
            ret = static_cast<detail::SslError>(error_offset + 2);
            return ret;
        }
        buffer_len += current_len;

        new_text = std::string((char*)buffer, buffer_len);

        void cleanup();

        return ret;
    }

    void cleanup();
};

}  // namespace nds

namespace std {
template <>
struct is_error_condition_enum<nds::detail::SslErrorConditional> : public true_type {};
template <>
struct is_error_code_enum<nds::detail::SslError> : public true_type {};
}  // namespace std
