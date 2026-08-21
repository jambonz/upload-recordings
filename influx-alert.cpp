#include "influx-alert.h"

#include <curl/curl.h>

#include <cstdlib>
#include <sstream>

namespace {

constexpr long ALERT_POST_CONNECT_TIMEOUT_SECS = 2;
constexpr long ALERT_POST_TOTAL_TIMEOUT_SECS = 5;

size_t discardResponseBody(char*, size_t size, size_t nmemb, void*) {
    return size * nmemb;
}

} // namespace

std::string influxEscapeTag(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c == ',' || c == ' ' || c == '=') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

std::string influxEscapeFieldString(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c == '\\' || c == '"') out.push_back('\\');
        // line protocol is single-line: fold newlines rather than corrupt the point
        out.push_back(c == '\n' || c == '\r' ? ' ' : c);
    }
    return out;
}

std::string buildAlertLine(const std::string& accountSid, const std::string& alertType,
                            const std::string& vendor, const std::string& message,
                            const std::string& detail, int64_t tsNanos) {
    std::ostringstream line;
    line << "alerts"
         << ",account_sid=" << influxEscapeTag(accountSid)
         << ",alert_type=" << influxEscapeTag(alertType)
         << ",vendor=" << influxEscapeTag(vendor)
         << " message=\"" << influxEscapeFieldString(message) << "\""
         << ",detail=\"" << influxEscapeFieldString(detail) << "\""
         << " " << tsNanos;
    return line.str();
}

void sendInfluxAlert(const std::shared_ptr<spdlog::logger>& log, const std::string& line) {
    const char* base = std::getenv("INFLUXDB_URL");
    if (!base || !*base) {
        log->error("influx-alert: INFLUXDB_URL not set -- alert not written: {}", line);
        return;
    }

    std::string url = std::string(base);
    if (!url.empty() && url.back() == '/') url.pop_back();
    url += "/write?db=alerts&precision=n";

    CURL* curl = curl_easy_init();
    if (!curl) {
        log->error("influx-alert: curl_easy_init failed");
        return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, line.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(line.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discardResponseBody);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, ALERT_POST_CONNECT_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, ALERT_POST_TOTAL_TIMEOUT_SECS);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log->error("influx-alert: write failed ({}): {}", curl_easy_strerror(res), line);
    } else {
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        if (httpCode < 200 || httpCode >= 300) {
            log->error("influx-alert: influx returned {} for: {}", httpCode, line);
        }
    }
    curl_easy_cleanup(curl);
}
