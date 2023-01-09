#include <nds.h>
#include <stdio.h>
#include <string.h>

#include "SslExample.h"

volatile int frame = 0;

void Vblank() {
    frame++;
}

int main(void) {
    nds::SslExample a;
    std::string str("Test Enc/Dec string!");

    irqSet(IRQ_VBLANK, Vblank);
    consoleDemoInit();

    iprintf(" [*] Start test OpenSSL build:\n");

    auto [code_enc, enc] = a.encrypt(str);
    iprintf(" [*] - enc result: %s\n", code_enc.message().c_str());

    if (!code_enc.value()) {
        auto [code_dec, dec] = a.decrypt(enc);
        iprintf(" [*] - dec result: %s\n", code_dec.message().c_str());

        if (code_dec.value()) {
            iprintf(" [*] - dec result code: %s\n", code_dec.value());
        } else {
            iprintf(" [*] - dec result text: %s\n", dec.c_str());
            iprintf(" [*] - enc result text: %s\n", enc.c_str());
        }
    } else {
        iprintf(" [*] - enc result code: %s\n", code_enc.value());
    }

    while (1) {
        swiWaitForVBlank();
    }

    return 0;
}
