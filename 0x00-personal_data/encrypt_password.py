#!/usr/bin/env python3
"""A module for securely encrypting and validating passwords using bcrypt.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with a randomly generated salt.
    
    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verifies if a given plain text password matches a hashed password.
    
    Args:
        hashed_password (bytes): The previously hashed password.
        password (str): The plain text password to verify against the hash.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
