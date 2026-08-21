#ifndef INFLUX_ALERT_H
#define INFLUX_ALERT_H

#include <cstdint>
#include <memory>
#include <string>

#include <spdlog/spdlog.h>

// Writes jambonz portal alerts from the recorder: the same InfluxDB `alerts` measurement
// @jambonz/time-series writes (tags: account_sid, alert_type, vendor; fields: message,
// detail), so eval-notify failures show up in the portal's Alerts view like every other
// platform alert. Endpoint comes from env INFLUXDB_URL (e.g. "http://10.0.0.5:8086");
// when unset, alerts are skipped with an error log (per EVAL-INTEGRATION-DESIGN.md §5.5).

// Escapes per the influx line protocol (tag values: comma/space/equals; field strings:
// backslash/double-quote). Exposed for the test binary.
std::string influxEscapeTag(const std::string& in);
std::string influxEscapeFieldString(const std::string& in);

// Builds one line-protocol point for the alerts measurement. `tsNanos` is nanoseconds
// since epoch. Pure function of its inputs.
std::string buildAlertLine(const std::string& accountSid, const std::string& alertType,
                            const std::string& vendor, const std::string& message,
                            const std::string& detail, int64_t tsNanos);

// POSTs the line to $INFLUXDB_URL/write?db=alerts. Never throws; failures are logged.
void sendInfluxAlert(const std::shared_ptr<spdlog::logger>& log, const std::string& line);

#endif // INFLUX_ALERT_H
