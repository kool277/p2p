/* A command-line client over the C ABI. It speaks the CLI contract in
 * docs/CLIENT-ADAPTER.md, so interop runs can drive it like any other client.
 *
 *   qalqon-cli-c enroll --server <url> --ca <hex file> --data <dir> --token <token>
 *   qalqon-cli-c call   --server <url> --ca <hex file> --data <dir> --user <id> --peer <id> [--records N] [--relay-only]
 *   qalqon-cli-c answer --server <url> --ca <hex file> --data <dir> --user <id> [--relay-only] [--wait-ms N]
 *
 * The password comes from the QALQON_PASSWORD environment variable. This file is the
 * template for any C or C++ integration: the C API is the adapter, and there is no
 * protocol logic here.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "qalqon.h"

static const char *flag(int argc, char **argv, const char *name) {
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static int has_flag(int argc, char **argv, const char *name) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int fail(const char *where, qalqon_status_t status) {
    printf("{\"result\":\"error\",\"error\":\"%s: %s\"}\n", where, qalqon_status_name(status));
    return 1;
}

static int fail_text(const char *message) {
    printf("{\"result\":\"error\",\"error\":\"%s\"}\n", message);
    return 1;
}

static char *read_file_trimmed(const char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *text = malloc((size_t)size + 1);
    size_t got = fread(text, 1, (size_t)size, file);
    fclose(file);
    while (got > 0 && (text[got - 1] == '\n' || text[got - 1] == ' ')) {
        got--;
    }
    text[got] = '\0';
    return text;
}

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* The ca file is hex, and the API's JSON wants base64. */
static char *hex_to_base64(const char *hex) {
    size_t bytes = strlen(hex) / 2;
    unsigned char *raw = malloc(bytes + 1);
    for (size_t i = 0; i < bytes; i++) {
        unsigned value = 0;
        sscanf(hex + 2 * i, "%2x", &value);
        raw[i] = (unsigned char)value;
    }
    char *out = malloc(bytes / 3 * 4 + 8);
    size_t n = 0;
    for (size_t i = 0; i < bytes; i += 3) {
        unsigned a = raw[i];
        unsigned b = i + 1 < bytes ? raw[i + 1] : 0;
        unsigned c = i + 2 < bytes ? raw[i + 2] : 0;
        out[n++] = BASE64[a >> 2];
        out[n++] = BASE64[((a & 3) << 4) | (b >> 4)];
        out[n++] = i + 1 < bytes ? BASE64[((b & 15) << 2) | (c >> 6)] : '=';
        out[n++] = i + 2 < bytes ? BASE64[c & 63] : '=';
    }
    out[n] = '\0';
    free(raw);
    return out;
}

static char *config_json(int argc, char **argv) {
    const char *server = flag(argc, argv, "--server");
    const char *ca = flag(argc, argv, "--ca");
    const char *data = flag(argc, argv, "--data");
    if (server == NULL || ca == NULL || data == NULL) {
        return NULL;
    }
    char *ca_hex = read_file_trimmed(ca);
    if (ca_hex == NULL) {
        return NULL;
    }
    char *ca_b64 = hex_to_base64(ca_hex);
    free(ca_hex);
    const char *relay = has_flag(argc, argv, "--relay-only") ? ",\"relayPolicy\":\"relayOnly\"" : "";
    size_t size = strlen(server) + strlen(ca_b64) + strlen(data) + 256;
    char *json = malloc(size);
    snprintf(json, size,
             "{\"serverUrl\":\"%s\",\"caBundle\":\"%s\",\"keyStore\":{\"kind\":\"osDefault\"},\"dataDir\":\"%s\"%s}",
             server, ca_b64, data, relay);
    free(ca_b64);
    return json;
}

static char *credentials_json(int argc, char **argv) {
    const char *user = flag(argc, argv, "--user");
    const char *password = getenv("QALQON_PASSWORD");
    if (user == NULL || password == NULL) {
        return NULL;
    }
    size_t len = strlen(password);
    /* The secret is bytes, so it travels as base64 like every other bytes field. */
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02x", (unsigned char)password[i]);
    }
    char *secret = hex_to_base64(hex);
    free(hex);
    size_t size = strlen(user) + strlen(secret) + 64;
    char *json = malloc(size);
    snprintf(json, size, "{\"userId\":\"%s\",\"secret\":\"%s\"}", user, secret);
    free(secret);
    return json;
}

static int run_enroll(int argc, char **argv) {
    const char *token = flag(argc, argv, "--token");
    const char *name = flag(argc, argv, "--name");
    char *config = config_json(argc, argv);
    if (token == NULL || config == NULL) {
        return fail_text("enroll needs --server, --ca, --data and --token");
    }
    char request[4096];
    snprintf(request, sizeof request, "{\"enrollmentToken\":\"%s\",\"deviceName\":\"%s\"}", token,
             name != NULL ? name : "cli-c");
    qalqon_buffer_t result = {0};
    qalqon_status_t status = qalqon_enroll_device(config, request, &result);
    free(config);
    if (status != QALQON_OK) {
        return fail("enrollDevice", status);
    }
    printf("{\"enrolled\":%s}\n", (const char *)result.data);
    qalqon_buffer_free(&result);
    return 0;
}

static qalqon_session_t *log_in(int argc, char **argv, int *code) {
    char *config = config_json(argc, argv);
    char *credentials = credentials_json(argc, argv);
    if (config == NULL || credentials == NULL) {
        *code = fail_text("--server, --ca, --data, --user and QALQON_PASSWORD are required");
        return NULL;
    }
    qalqon_session_t *session = NULL;
    qalqon_status_t status = qalqon_connect(config, credentials, &session);
    free(config);
    free(credentials);
    if (status != QALQON_OK) {
        *code = fail("connect", status);
        return NULL;
    }
    printf("{\"state\":\"connected\"}\n");
    fflush(stdout);
    return session;
}

/* A string field out of an info object, using the library's own JSON reader. */
static char *field_of(const char *json, const char *key) {
    qalqon_buffer_t value = {0};
    if (qalqon_json_get_string(json, key, &value) != QALQON_OK) {
        return NULL;
    }
    char *copy = strdup((const char *)value.data);
    qalqon_buffer_free(&value);
    return copy;
}

/* channel.info holds the peer as a nested object, so its fields are read in two steps. */
static void read_peer_fields(const char *info, char **path, char **status, char **safety) {
    *path = field_of(info, "path");
    const char *peer = strstr(info, "\"peer\":");
    *status = NULL;
    *safety = NULL;
    if (peer == NULL) {
        return;
    }
    peer += strlen("\"peer\":");
    size_t len = 0;
    int depth = 0;
    do {
        if (peer[len] == '{') {
            depth++;
        } else if (peer[len] == '}') {
            depth--;
        }
        len++;
    } while (depth > 0 && peer[len] != '\0');
    char *object = strndup(peer, len);
    *status = field_of(object, "status");
    *safety = field_of(object, "safetyNumber");
    free(object);
}

/* How many lines the export holds. The events are JSON Lines, in a base64 field. */
static unsigned count_exported_events(const char *export_json) {
    char *events = field_of(export_json, "events");
    if (events == NULL) {
        return 0;
    }
    unsigned lines = 0;
    unsigned bits = 0;
    unsigned value = 0;
    for (const char *c = events; *c != '\0' && *c != '='; c++) {
        const char *digit = strchr(BASE64, *c);
        if (digit == NULL) {
            break;
        }
        value = (value << 6) | (unsigned)(digit - BASE64);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (((value >> bits) & 0xFF) == '\n') {
                lines++;
            }
        }
    }
    free(events);
    return lines;
}

static long long epoch_of(const char *info) {
    uint64_t epoch = 0;
    return qalqon_json_get_u64(info, "keyEpoch", &epoch) == QALQON_OK ? (long long)epoch : -1;
}

static void make_record(char *out, size_t size, unsigned n) {
    char padding[65];
    memset(padding, 'x', 64);
    padding[64] = '\0';
    snprintf(out, size, "record %06u %s", n, padding);
}

static int run_call(int argc, char **argv) {
    int code = 1;
    qalqon_session_t *session = log_in(argc, argv, &code);
    if (session == NULL) {
        return code;
    }
    const char *peer = flag(argc, argv, "--peer");
    const char *count = flag(argc, argv, "--records");
    unsigned records = count != NULL ? (unsigned)strtoul(count, NULL, 10) : 1000;
    if (peer == NULL) {
        return fail_text("call needs --peer");
    }
    char peer_json[512];
    snprintf(peer_json, sizeof peer_json, "{\"userId\":\"%s\"}", peer);
    const char *options = "{\"label\":\"interop\",\"ordered\":true,\"reliable\":true}";

    qalqon_channel_t *channel = NULL;
    qalqon_status_t status = qalqon_session_open_channel(session, peer_json, options, &channel);
    if (status != QALQON_OK) {
        return fail("openChannel", status);
    }

    unsigned sent = 0;
    unsigned received = 0;
    int rekeyed = 0;
    time_t deadline = time(NULL) + 120;
    char record[128];
    while (received < records) {
        if (time(NULL) > deadline) {
            return fail_text("not every record came back in time");
        }
        while (sent < records && sent - received < 64) {
            make_record(record, sizeof record, sent);
            status = qalqon_channel_send(channel, (const uint8_t *)record, strlen(record));
            if (status != QALQON_OK) {
                return fail("send", status);
            }
            sent++;
        }
        qalqon_buffer_t message = {0};
        bool present = false;
        status = qalqon_channel_receive(channel, 50, &message, &present);
        if (status != QALQON_OK) {
            return fail("receive", status);
        }
        if (present) {
            make_record(record, sizeof record, received);
            if (message.len != strlen(record) || memcmp(message.data, record, message.len) != 0) {
                qalqon_buffer_free(&message);
                return fail_text("a reply did not match what was sent");
            }
            received++;
        }
        qalqon_buffer_free(&message);
        if (!rekeyed && received >= records / 2) {
            status = qalqon_session_rotate_keys(session, peer_json);
            if (status != QALQON_OK) {
                return fail("rotateKeys", status);
            }
            rekeyed = 1;
        }
    }

    qalqon_buffer_t info = {0};
    status = qalqon_channel_info(channel, &info);
    if (status != QALQON_OK) {
        return fail("info", status);
    }
    char *path, *peer_status, *safety;
    read_peer_fields((const char *)info.data, &path, &peer_status, &safety);
    long long epoch = epoch_of((const char *)info.data);

    qalqon_buffer_t export_json = {0};
    status = qalqon_session_export_audit(session, "{}", &export_json);
    if (status != QALQON_OK) {
        return fail("exportAudit", status);
    }
    unsigned audit_entries = count_exported_events((const char *)export_json.data);
    qalqon_buffer_free(&export_json);

    status = qalqon_session_close(session);
    if (status != QALQON_OK) {
        return fail("close", status);
    }
    printf("{\"result\":\"ok\",\"records\":%u,\"path\":\"%s\",\"key_epoch\":%lld,\"peer_status\":\"%s\","
           "\"safety_number\":\"%s\",\"audit_entries\":%u,\"provider\":\"%s\"}\n",
           received, path, epoch, peer_status, safety, audit_entries, qalqon_provider_name());
    qalqon_buffer_free(&info);
    free(path);
    free(peer_status);
    free(safety);
    qalqon_channel_free(channel);
    qalqon_session_free(session);
    return 0;
}

static int run_answer(int argc, char **argv) {
    int code = 1;
    qalqon_session_t *session = log_in(argc, argv, &code);
    if (session == NULL) {
        return code;
    }
    const char *wait_ms = flag(argc, argv, "--wait-ms");
    time_t deadline = time(NULL) + (wait_ms != NULL ? strtol(wait_ms, NULL, 10) / 1000 : 60);
    char *request_id = NULL;
    while (request_id == NULL) {
        if (time(NULL) > deadline) {
            return fail_text("no call arrived in time");
        }
        qalqon_buffer_t event = {0};
        bool present = false;
        qalqon_status_t status = qalqon_session_next_event(session, 200, &event, &present);
        if (status != QALQON_OK) {
            return fail("nextEvent", status);
        }
        if (present) {
            char *type = field_of((const char *)event.data, "type");
            if (type != NULL && strcmp(type, "channelRequested") == 0) {
                request_id = field_of((const char *)event.data, "requestId");
            }
            free(type);
        }
        qalqon_buffer_free(&event);
    }

    qalqon_channel_t *channel = NULL;
    qalqon_status_t status = qalqon_session_accept_channel(session, request_id, &channel);
    free(request_id);
    if (status != QALQON_OK) {
        return fail("acceptChannel", status);
    }
    qalqon_buffer_t info = {0};
    status = qalqon_channel_info(channel, &info);
    if (status != QALQON_OK) {
        return fail("info", status);
    }
    char *path, *peer_status, *safety;
    read_peer_fields((const char *)info.data, &path, &peer_status, &safety);

    unsigned long long echoed = 0;
    for (;;) {
        qalqon_buffer_t message = {0};
        bool present = false;
        status = qalqon_channel_receive(channel, 200, &message, &present);
        if (status != QALQON_OK) {
            qalqon_buffer_free(&message);
            break; /* The peer closed. */
        }
        if (present) {
            status = qalqon_channel_send(channel, message.data, message.len);
            if (status != QALQON_OK) {
                qalqon_buffer_free(&message);
                return fail("send", status);
            }
            echoed++;
        }
        qalqon_buffer_free(&message);
    }
    printf("{\"result\":\"ok\",\"records\":%llu,\"path\":\"%s\",\"peer_status\":\"%s\",\"safety_number\":\"%s\",\"provider\":\"%s\"}\n",
           echoed, path, peer_status, safety, qalqon_provider_name());
    qalqon_session_close(session);
    qalqon_buffer_free(&info);
    free(path);
    free(peer_status);
    free(safety);
    qalqon_channel_free(channel);
    qalqon_session_free(session);
    return 0;
}

int main(int argc, char **argv) {
    if (qalqon_abi_version() != QALQON_ABI_VERSION) {
        return fail_text("this program was built against a different libqalqon");
    }
    if (argc < 2) {
        return fail_text("usage: qalqon-cli-c <enroll|call|answer> ...");
    }
    if (strcmp(argv[1], "enroll") == 0) {
        return run_enroll(argc, argv);
    }
    if (strcmp(argv[1], "call") == 0) {
        return run_call(argc, argv);
    }
    if (strcmp(argv[1], "answer") == 0) {
        return run_answer(argc, argv);
    }
    return fail_text("usage: qalqon-cli-c <enroll|call|answer> ...");
}
