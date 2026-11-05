// Runs the shared vectors through the C ABI, using the C++ wrapper. Also checks the rules
// of the ABI itself, so a mismatched library is caught here rather than later.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "qalqon.hpp"

static int field_int(const std::string &json, const std::string &key) {
    uint64_t value = 0;
    qalqon::check(qalqon_json_get_u64(json.c_str(), key.c_str(), &value));
    return static_cast<int>(value);
}

int main(int argc, char **argv) {
    if (qalqon_abi_version() != QALQON_ABI_VERSION) {
        std::cerr << "the header and the library disagree on the ABI version\n";
        return 1;
    }
    // Error codes cross as the IDL's numbers, with the IDL's names.
    if (std::string(qalqon_status_name(QALQON_PEER_REVOKED)) != "peerRevoked" || QALQON_PEER_REVOKED != 204) {
        std::cerr << "error codes do not match the IDL\n";
        return 1;
    }
    int failed = 0;
    for (int i = 1; i < argc; i++) {
        std::ifstream file(argv[i]);
        std::stringstream text;
        text << file.rdbuf();
        const std::string report = qalqon::conformance_run(text.str());
        const int passed = field_int(report, "passed");
        const bool clean = report.find("\"failed\":[]") != std::string::npos;
        std::printf("%s: %d passed%s\n", argv[i], passed, clean ? "" : ", with failures");
        if (!clean || passed == 0) {
            std::cerr << report << "\n";
            failed++;
        }
    }
    return failed == 0 ? 0 : 1;
}
