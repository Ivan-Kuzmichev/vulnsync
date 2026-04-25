"""Parser for Apache/nginx Combined Log Format.

Format: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
Example:
127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /index.php?id=1 HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import parse_qs, urlparse


_LINE_RE = re.compile(
    r"^(?P<ip>\S+)\s+"
    r"\S+\s+\S+\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r"\"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)\"\s+"
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\S+)\s*"
    r"(?:\"(?P<referer>[^\"]*)\"\s*)?"
    r"(?:\"(?P<user_agent>[^\"]*)\")?\s*$"
)


@dataclass
class LogEvent:
    raw: str
    line_no: int
    ip: str
    timestamp: datetime
    method: str
    path: str
    query: str
    status: int
    size: int
    referer: str
    user_agent: str

    def to_dict(self) -> dict:
        return {
            "line_no": self.line_no,
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "status": self.status,
            "size": self.size,
            "user_agent": self.user_agent,
            "raw": self.raw,
        }


def _parse_time(raw: str) -> datetime:
    # 10/Oct/2023:13:55:36 -0700
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")


def parse(text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        try:
            ts = _parse_time(m.group("time"))
        except ValueError:
            continue
        url = urlparse(m.group("path"))
        try:
            size = int(m.group("size")) if m.group("size") != "-" else 0
        except ValueError:
            size = 0
        events.append(
            LogEvent(
                raw=line,
                line_no=i,
                ip=m.group("ip"),
                timestamp=ts,
                method=m.group("method"),
                path=url.path,
                query=url.query,
                status=int(m.group("status")),
                size=size,
                referer=m.group("referer") or "",
                user_agent=m.group("user_agent") or "",
            )
        )
    return events
