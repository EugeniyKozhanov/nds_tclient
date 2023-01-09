#include "../src/SslExample.h"

#include <gtest/gtest.h>

TEST(SslExample, EncryptAndDecrypt) {
    std::string str("Test Enc/Dec string!");
    nds::SslExample a;

    auto [code_encr, encr] = a.encrypt(str);

    EXPECT_EQ(static_cast<int>(code_encr.value()), static_cast<int>(nds::detail::SslError::Success));

    auto [code_decr, decr] = a.decrypt(encr);

    EXPECT_EQ(static_cast<int>(code_decr.value()), static_cast<int>(nds::detail::SslError::Success));
    EXPECT_STREQ(str.c_str(), decr.c_str());
}

TEST(SslExample, ErrorCodesOffset) {
    int encr_offset = static_cast<int>(nds::detail::SslError::EncInit);

    EXPECT_EQ(encr_offset + 1, static_cast<int>(nds::detail::SslError::EncUpdate));
    EXPECT_EQ(encr_offset + 2, static_cast<int>(nds::detail::SslError::EncFinal));

    int decr_offset = static_cast<int>(nds::detail::SslError::DecInit);

    EXPECT_EQ(decr_offset + 1, static_cast<int>(nds::detail::SslError::DecUpdate));
    EXPECT_EQ(decr_offset + 2, static_cast<int>(nds::detail::SslError::DecFinal));
}
