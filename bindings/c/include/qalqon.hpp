// RAII wrappers over qalqon.h, for C++ and Qt. This holds no protocol logic. Structured
// values stay JSON text, so bring your own parser or use qalqon_json_get_*.
#ifndef QALQON_HPP
#define QALQON_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <optional>
#include <vector>

#include "qalqon.h"

namespace qalqon {

class Error : public std::runtime_error {
public:
    explicit Error(qalqon_status_t status) : std::runtime_error(qalqon_status_name(status)), status_(status) {}
    qalqon_status_t status() const noexcept { return status_; }

private:
    qalqon_status_t status_;
};

inline void check(qalqon_status_t status) {
    if (status != QALQON_OK) {
        throw Error(status);
    }
}

class Buffer {
public:
    Buffer() = default;
    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;
    ~Buffer() { qalqon_buffer_free(&raw_); }
    qalqon_buffer_t *out() noexcept { return &raw_; }
    std::string text() const { return raw_.data ? std::string(reinterpret_cast<const char *>(raw_.data), raw_.len) : std::string(); }
    std::vector<uint8_t> bytes() const { return raw_.data ? std::vector<uint8_t>(raw_.data, raw_.data + raw_.len) : std::vector<uint8_t>(); }

private:
    qalqon_buffer_t raw_{nullptr, 0};
};

class Channel {
public:
    explicit Channel(qalqon_channel_t *raw) noexcept : raw_(raw) {}
    Channel(const Channel &) = delete;
    Channel &operator=(const Channel &) = delete;
    Channel(Channel &&other) noexcept : raw_(other.raw_) { other.raw_ = nullptr; }
    ~Channel() { qalqon_channel_free(raw_); }

    void send(const std::vector<uint8_t> &payload) { check(qalqon_channel_send(raw_, payload.data(), payload.size())); }

    std::optional<std::vector<uint8_t>> receive(uint32_t timeout_ms) {
        Buffer message;
        bool present = false;
        check(qalqon_channel_receive(raw_, timeout_ms, message.out(), &present));
        if (!present) {
            return std::nullopt;
        }
        return message.bytes();
    }

    std::string info() {
        Buffer out;
        check(qalqon_channel_info(raw_, out.out()));
        return out.text();
    }

    void close() { check(qalqon_channel_close(raw_)); }

private:
    qalqon_channel_t *raw_;
};

class Session {
public:
    Session(const std::string &config_json, const std::string &credentials_json) {
        check(qalqon_connect(config_json.c_str(), credentials_json.c_str(), &raw_));
    }
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;
    ~Session() { qalqon_session_free(raw_); }

    Channel open_channel(const std::string &peer_json, const std::string &options_json) {
        qalqon_channel_t *channel = nullptr;
        check(qalqon_session_open_channel(raw_, peer_json.c_str(), options_json.c_str(), &channel));
        return Channel(channel);
    }

    Channel accept_channel(const std::string &request_id) {
        qalqon_channel_t *channel = nullptr;
        check(qalqon_session_accept_channel(raw_, request_id.c_str(), &channel));
        return Channel(channel);
    }

    std::optional<std::string> next_event(uint32_t timeout_ms) {
        Buffer out;
        bool present = false;
        check(qalqon_session_next_event(raw_, timeout_ms, out.out(), &present));
        if (!present) {
            return std::nullopt;
        }
        return out.text();
    }

    void close() { check(qalqon_session_close(raw_)); }

private:
    qalqon_session_t *raw_ = nullptr;
};

/// conformanceRun: checks one vector file inside this runtime, and returns a JSON report.
inline std::string conformance_run(const std::string &vectors) {
    Buffer out;
    check(qalqon_conformance_run(vectors.c_str(), out.out()));
    return out.text();
}

}  // namespace qalqon

#endif
