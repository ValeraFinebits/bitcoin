// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <payjoin.hpp>
#include <univalue.h>

#include <exception>
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "Usage: payjoin_test_services CERTIFICATE_FILE\n";
        return 1;
    }
    try {
        const auto services = ::payjoin::TestServices::initialize();
        services->wait_for_services_ready();
        const auto certificate = services->cert();
        std::ofstream file{argv[1], std::ios::binary};
        file.write(reinterpret_cast<const char*>(certificate.data()), certificate.size());
        file.close();
        if (!file) {
            std::cerr << "Could not write TestServices certificate\n";
            return 1;
        }
        UniValue ready{UniValue::VOBJ};
        ready.pushKV("directory", services->directory_url());
        ready.pushKV("relay", services->ohttp_relay_url());
        std::cout << ready.write() << std::endl;

        std::string command;
        while (std::getline(std::cin, command) && command != "stop") {
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
