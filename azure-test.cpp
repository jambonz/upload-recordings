// Standalone test for AzureUploader request signing: no Azure, no MySQL. libcurl is pointed
// at a local capture proxy (http_proxy), which records each request and answers 201.
// Run via `make check`. A failure prints the line number and exits non-zero.
//
// Regression: x-ms-date was stamped once when the uploader was created (call start) and
// reused at upload time (call end), so Azure rejected uploads of calls > 15 minutes with
// 403 "Request date header too old". Each request must carry the time it was sent, and be
// signed with that same date.

#include "azure-uploader.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <spdlog/sinks/null_sink.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

namespace {

const char* kAccount = "testacct";
const char* kContainer = "recordings";
// base64 of 32 bytes 0x01..0x20
const char* kAccountKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

struct CapturedRequest {
    std::string method;
    std::string url;          // absolute URI, as sent to a proxy
    std::map<std::string, std::string> headers; // lower-cased names
    size_t bodySize = 0;
    std::time_t receivedAt = 0;
};

std::mutex gMutex;
std::vector<CapturedRequest> gRequests;

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r");
    size_t e = s.find_last_not_of(" \t\r");
    return b == std::string::npos ? "" : s.substr(b, e - b + 1);
}

// Minimal HTTP/1.1 proxy endpoint: one request per connection, always 201.
void handleConnection(int fd) {
    std::string buf;
    char tmp[65536];
    size_t headerEnd;
    while ((headerEnd = buf.find("\r\n\r\n")) == std::string::npos) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) { close(fd); return; }
        buf.append(tmp, n);
    }
    CapturedRequest req;
    req.receivedAt = std::time(nullptr);
    std::istringstream hs(buf.substr(0, headerEnd));
    std::string line;
    std::getline(hs, line);
    std::istringstream rl(line);
    rl >> req.method >> req.url;
    while (std::getline(hs, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        req.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
    }
    if (lower(req.headers["expect"]) == "100-continue") {
        const char* cont = "HTTP/1.1 100 Continue\r\n\r\n";
        send(fd, cont, std::strlen(cont), 0);
    }
    size_t contentLength = std::stoul(req.headers.count("content-length") ? req.headers["content-length"] : "0");
    size_t have = buf.size() - (headerEnd + 4);
    while (have < contentLength) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        have += n;
    }
    req.bodySize = have;
    {
        std::lock_guard<std::mutex> lk(gMutex);
        gRequests.push_back(req);
    }
    const char* resp = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    send(fd, resp, std::strlen(resp), 0);
    close(fd);
}

int startProxy(int& port) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return -1;
    if (listen(lfd, 16) != 0) return -1;
    socklen_t len = sizeof(addr);
    getsockname(lfd, reinterpret_cast<sockaddr*>(&addr), &len);
    port = ntohs(addr.sin_port);
    std::thread([lfd] {
        for (;;) {
            int fd = accept(lfd, nullptr, nullptr);
            if (fd < 0) return;
            handleConnection(fd);
        }
    }).detach();
    return lfd;
}

// RFC 1123 "Thu, 01 Oct 2026 13:19:52 GMT" -> epoch seconds (UTC); -1 on parse failure
std::time_t parseRfc1123(const std::string& s) {
    std::tm tm{};
    if (!strptime(s.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm)) return -1;
    return timegm(&tm);
}

std::string base64(const unsigned char* data, size_t len) {
    std::string out(4 * ((len + 2) / 3), '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), data, static_cast<int>(len));
    out.resize(n);
    return out;
}

std::vector<unsigned char> unbase64(const std::string& s) {
    std::vector<unsigned char> out(3 * s.size() / 4);
    int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()), static_cast<int>(s.size()));
    size_t pad = (s.size() >= 2 && s[s.size() - 1] == '=') + (s.size() >= 2 && s[s.size() - 2] == '=');
    out.resize(n - pad);
    return out;
}

// Independent Shared Key computation from what was actually sent on the wire. Follows
// https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
std::string expectedAuthorization(const CapturedRequest& r) {
    // url: http://testacct.blob.core.windows.net/recordings/...?comp=block&blockid=...
    std::string pathAndQuery = r.url.substr(r.url.find(".net") + 4);
    std::string path = pathAndQuery.substr(0, pathAndQuery.find('?'));
    std::map<std::string, std::string> query;
    size_t q = pathAndQuery.find('?');
    if (q != std::string::npos) {
        std::istringstream qs(pathAndQuery.substr(q + 1));
        std::string pair;
        while (std::getline(qs, pair, '&')) {
            size_t eq = pair.find('=');
            query[lower(pair.substr(0, eq))] = eq == std::string::npos ? "" : pair.substr(eq + 1);
        }
    }
    auto hdr = [&](const char* name) {
        auto it = r.headers.find(name);
        return it == r.headers.end() ? std::string() : it->second;
    };
    std::ostringstream sts;
    sts << r.method << "\n"
        << hdr("content-encoding") << "\n"
        << hdr("content-language") << "\n"
        << hdr("content-length") << "\n"
        << hdr("content-md5") << "\n"
        << hdr("content-type") << "\n"
        << "\n" // Date (x-ms-date is used instead)
        << hdr("if-modified-since") << "\n"
        << hdr("if-match") << "\n"
        << hdr("if-none-match") << "\n"
        << hdr("if-unmodified-since") << "\n"
        << hdr("range") << "\n";
    for (const auto& h : r.headers) {   // std::map: already sorted by lower-cased name
        if (h.first.rfind("x-ms-", 0) == 0) sts << h.first << ":" << h.second << "\n";
    }
    sts << "/" << kAccount << path;
    for (const auto& p : query) sts << "\n" << p.first << ":" << p.second;

    std::vector<unsigned char> key = unbase64(kAccountKey);
    std::string s = sts.str();
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int macLen = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(s.data()), s.size(), mac, &macLen);
    return std::string("SharedKey ") + kAccount + ":" + base64(mac, macLen);
}

} // namespace

int main() {
    int port = 0;
    CHECK(startProxy(port) >= 0);
    setenv("http_proxy", ("http://127.0.0.1:" + std::to_string(port)).c_str(), 1);
    unsetenv("no_proxy");
    unsetenv("NO_PROXY");

    auto log = std::make_shared<spdlog::logger>("azure-test", std::make_shared<spdlog::sinks::null_sink_mt>());
    std::string folder = (std::filesystem::temp_directory_path() / "azure-test").string();
    std::filesystem::create_directories(folder);

    std::string conn = std::string("DefaultEndpointsProtocol=http;AccountName=") + kAccount +
        ";AccountKey=" + kAccountKey + ";EndpointSuffix=core.windows.net";

    // ---- uploader created at "call start"
    const std::time_t createdAt = std::time(nullptr);
    AzureUploader uploader(nullptr, log, folder, RecordFileType::WAV, conn, kContainer);
    Metadata_t md{};
    md.call_sid = "call-1";
    md.sample_rate = 8000;
    uploader.setMetadata(md);

    // ---- "call end" comes later. Real calls are > 15 min; any gap past the 1s resolution
    // of x-ms-date distinguishes "stamped at creation" from "stamped when sent".
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // 5 MB of PCM -> two blocks (4 MB block size) + the block-list commit
    std::vector<char> pcm(5 * 1024 * 1024, 0);
    const std::time_t uploadStartedAt = std::time(nullptr);
    CHECK(uploader.upload(pcm, true));

    std::lock_guard<std::mutex> lk(gMutex);
    CHECK(gRequests.size() == 3);
    int blocks = 0, commits = 0;
    for (const auto& r : gRequests) {
        CHECK(r.method == "PUT");
        if (r.url.find("comp=blocklist") != std::string::npos) commits++;
        else if (r.url.find("comp=block&") != std::string::npos) blocks++;

        // x-ms-date is the time the request went out, not when the uploader was created
        CHECK(r.headers.count("x-ms-date") == 1);
        std::time_t sent = parseRfc1123(r.headers.at("x-ms-date"));
        CHECK(sent != -1);
        if (sent < uploadStartedAt) {
            std::fprintf(stderr, "x-ms-date %s is %lds before the upload started (uploader created %lds before)\n",
                r.headers.at("x-ms-date").c_str(), static_cast<long>(uploadStartedAt - sent),
                static_cast<long>(uploadStartedAt - createdAt));
        }
        CHECK(sent >= uploadStartedAt);
        CHECK(sent <= r.receivedAt);

        // the signature covers the x-ms-date that was actually sent
        CHECK(r.headers.count("authorization") == 1);
        if (r.headers.at("authorization") != expectedAuthorization(r)) {
            std::fprintf(stderr, "signature mismatch for %s\n", r.url.c_str());
        }
        CHECK(r.headers.at("authorization") == expectedAuthorization(r));
    }
    CHECK(blocks == 2);
    CHECK(commits == 1);

    std::printf("azure_test: all checks passed (%zu requests)\n", gRequests.size());
    return 0;
}
