import json
import logging
from collections import OrderedDict
from typing import Any, Dict, TypeVar  # noqa: F401

from uaclient import util

REDACT_FIELDS = {"token"}


def redact_value(v):
    if isinstance(v, dict):
        return redact_dict_fields(v)
    elif isinstance(v, str):
        return util.redact_sensitive_logs(v)
    elif isinstance(v, list):
        return [redact_value(item) for item in v]
    else:
        return v


def redact_dict_fields(d: Dict) -> Dict:
    new_d = {}  # type: Dict[Any, Any]
    for k, v in d.items():
        if k in REDACT_FIELDS:
            new_d[k] = "REDACTED"
        else:
            new_d[k] = redact_value(v)
    return new_d


class RedactionFilter(logging.Filter):
    """A logging filter to redact confidential info"""

    def filter(self, record: logging.LogRecord):
        record.msg = util.redact_sensitive_logs(str(record.msg))
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            record.extra = redact_dict_fields(record.extra)
        return True


class JsonArrayFormatter(logging.Formatter):
    """Json Array Formatter for our logging mechanism
    Custom made for Pro logging needs
    """

    default_time_format = "%Y-%m-%dT%H:%M:%S"
    default_msec_format = "%s.%03d"
    required_fields = (
        "asctime",
        "levelname",
        "name",
        "funcName",
        "lineno",
        "message",
    )

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        record.asctime = self.formatTime(record)

        extra_message_dict = {}  # type: Dict[str, Any]
        if record.exc_info:
            extra_message_dict["exc_info"] = self.formatException(
                record.exc_info
            )
        if not extra_message_dict.get("exc_info") and record.exc_text:
            extra_message_dict["exc_info"] = record.exc_text
        if record.stack_info:
            extra_message_dict["stack_info"] = self.formatStack(
                record.stack_info
            )
        extra = record.__dict__.get("extra")
        if extra and isinstance(extra, dict):
            extra_message_dict.update(extra)

        # is ordered to maintain order of fields in log output
        local_log_record = OrderedDict()  # type: Dict[str, Any]
        # update the required fields in the order stated
        for field in self.required_fields:
            value = record.__dict__.get(field)
            local_log_record[field] = value

        local_log_record["extra"] = extra_message_dict
        return json.dumps(list(local_log_record.values()))


def with_extra(**kwargs):
    """
    A helper for including extra fields in a logging statement.

    Use like this:
    logging.debug("something happened!", **with_extra(thing_name="something"))

    That will result in a log line something like:
    ["2023-04-14T05:40:33.072", "DEBUG", "logger", "function", 123, "something happened!", {"thing_name": "something"}]  # noqa: E501
    """
    return {"extra": {"extra": kwargs}}
