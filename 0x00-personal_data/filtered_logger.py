#!/usr/bin/env python3
"""Module for filtering and logging sensitive user data records securely.

This module provides tools to connect to a database, retrieve user data,
and log it while protecting sensitive information (PII) through redaction.
"""
import os
import re
import logging
import mysql.connector
from typing import List

# Dictionary of regular expression patterns for data extraction and replacement
patterns = {
    'extract': lambda fields, sep: r'(?P<field>{})=[^{}]*'.format('|'.join(fields), sep),
    'replace': lambda redaction: r'\g<field>={}'.format(redaction),
}

# List of fields considered personally identifiable information (PII)
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Redacts specified fields in a log message by replacing their values.

    Args:
        fields (List[str]): List of field names to be redacted.
        redaction (str): The text that will replace the redacted field values.
        message (str): The log message containing fields to redact.
        separator (str): The character separating key-value pairs in the message.

    Returns:
        str: The redacted log message.
    """
    extract, replace = patterns["extract"], patterns["replace"]
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """
    Configures a logger to output user data logs with PII redaction.

    Returns:
        logging.Logger: A logger instance configured for user data with redaction.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevents log messages from being passed to the root logger
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes a connection to a MySQL database using environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: A database connection instance.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """
    Connects to the database and logs user records, redacting sensitive information.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            # Mapping column names to values for log output
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            # Construct the log message as a single string with key-value pairs
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts sensitive information in log messages.

    This formatter redacts specified fields in log messages to prevent
    sensitive information from being logged in plain text.
    """

    REDACTION = "***"  # Text to replace sensitive data
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"  # Separator used in log messages

    def __init__(self, fields: List[str]):
        """
        Initializes a RedactingFormatter instance.

        Args:
            fields (List[str]): Fields to redact in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Redacts sensitive fields in a log record.

        Args:
            record (logging.LogRecord): The log record to format and redact.

        Returns:
            str: The formatted log message with redacted fields.
        """
        msg = super(RedactingFormatter, self).format(record)
        redacted_msg = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return redacted_msg


if __name__ == "__main__":
    main()
