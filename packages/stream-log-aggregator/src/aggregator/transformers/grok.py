"""High-performance Grok / Regex log parser and JSON normalizer."""

import json
import re
from typing import Any, Callable, Dict, List, Optional
from aggregator import LogEvent
from aggregator.transformers import BaseTransformer

# RFC 3164: <134>Feb 15 14:02:30 server1 nginx[1234]: client disconnected
RE_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[\w\.\-]+)\s+(?P<app_name>[\w\.\-\(\)]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# RFC 5424: <165>1 2026-08-27T20:00:00.000Z host.example.com myapp 1234 ID47 - [exampleSDID@32473] Log message
RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s*(?:\[(?P<structured_data>[^\]]*)\])?\s*(?P<message>.*)$"
)

# Combined Apache / Nginx log format
RE_COMBINED_HTTP = re.compile(
    r'^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<auth_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+(?P<http_version>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes_sent>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


class GrokTransformer(BaseTransformer):
    """Parses standard log formats and JSON payloads into structured metadata."""

    def __init__(
        self,
        name: str = "grok-parser",
        custom_patterns: Optional[Dict[str, str]] = None,
        parse_json: bool = True,
        parse_syslog: bool = True,
        parse_http: bool = True,
    ):
        super().__init__(name=name)
        self.parse_json = parse_json
        self.parse_syslog = parse_syslog
        self.parse_http = parse_http
        self._custom_regexes: Dict[str, re.Pattern] = {}

        if custom_patterns:
            for pattern_name, regex_str in custom_patterns.items():
                self._custom_regexes[pattern_name] = re.compile(regex_str)

    def _parse_pri(self, pri_int: int) -> Dict[str, Any]:
        """Decode Syslog PRI into facility and severity according to RFC 5424."""
        facility = pri_int >> 3
        severity = pri_int & 7
        severity_names = [
            "Emergency", "Alert", "Critical", "Error",
            "Warning", "Notice", "Informational", "Debug"
        ]
        return {
            "facility_code": facility,
            "severity_code": severity,
            "severity": severity_names[severity] if severity < len(severity_names) else "Unknown",
        }

    def _try_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Attempt fast JSON parsing if string appears to be JSON."""
        stripped = text.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            return None
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return None

    def transform(self, event: LogEvent) -> LogEvent:
        """Parse event raw/message using Grok regexes or JSON normalization."""
        self._processed_count += 1
        text = event.message or event.raw
        if not text:
            return event

        # 1. Try JSON
        if self.parse_json:
            json_dict = self._try_parse_json(text)
            if json_dict is not None:
                self._modified_count += 1
                # Normalize extracted message
                msg_field = None
                for key in ["message", "msg", "log", "text", "description"]:
                    if key in json_dict and isinstance(json_dict[key], str):
                        msg_field = json_dict[key]
                        break

                if msg_field:
                    event.message = msg_field

                event.metadata.update(json_dict)
                if "json-parsed" not in event.tags:
                    event.tags.append("json-parsed")
                return event

        # 2. Try RFC 5424 Syslog
        if self.parse_syslog:
            m5424 = RE_RFC5424.match(text)
            if m5424:
                self._modified_count += 1
                data = m5424.groupdict()
                try:
                    pri_val = int(data.pop("pri", 0))
                    data.update(self._parse_pri(pri_val))
                except ValueError:
                    pass

                new_msg = data.pop("message", "")
                if new_msg:
                    event.message = new_msg.strip()
                event.metadata.update(data)
                if "syslog-rfc5424" not in event.tags:
                    event.tags.append("syslog-rfc5424")
                return event

            # 3. Try RFC 3164 Syslog
            m3164 = RE_RFC3164.match(text)
            if m3164:
                self._modified_count += 1
                data = m3164.groupdict()
                try:
                    pri_val = int(data.pop("pri", 0))
                    data.update(self._parse_pri(pri_val))
                except ValueError:
                    pass

                new_msg = data.pop("message", "")
                if new_msg:
                    event.message = new_msg.strip()
                event.metadata.update(data)
                if "syslog-rfc3164" not in event.tags:
                    event.tags.append("syslog-rfc3164")
                return event

        # 4. Try Combined HTTP
        if self.parse_http:
            mhttp = RE_COMBINED_HTTP.match(text)
            if mhttp:
                self._modified_count += 1
                data = mhttp.groupdict()
                try:
                    data["status"] = int(data["status"])
                except (ValueError, TypeError):
                    pass
                try:
                    if data["bytes_sent"] != "-":
                        data["bytes_sent"] = int(data["bytes_sent"])
                except (ValueError, TypeError):
                    pass

                event.metadata.update(data)
                if "http-access" not in event.tags:
                    event.tags.append("http-access")
                return event

        # 5. Try Custom Patterns
        for pattern_name, regex in self._custom_regexes.items():
            match = regex.match(text)
            if match:
                self._modified_count += 1
                data = match.groupdict()
                if "message" in data and data["message"]:
                    event.message = data.pop("message").strip()
                event.metadata.update(data)
                event.tags.append(f"grok-{pattern_name}")
                return event

        return event
