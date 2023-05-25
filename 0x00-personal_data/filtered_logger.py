#!/usr/bin/env python3
"""A module for filtering logs.
"""
import logging
import re
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    pattern = re.compile(r'\b(?:{})(?==)'.format('|'.join(fields)))
    return re.sub(pattern, redaction, message)


class RedactingFormatter(logging.Formatter):
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super().__init__(self.FORMAT)
        self.fields = set(fields)

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


def get_logger() -> logging.Logger:
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


if __name__ == "__main__":
    logger = get_logger()
    logger.info("name=john;email=john@example.com;password=secret;phone=123456789")
