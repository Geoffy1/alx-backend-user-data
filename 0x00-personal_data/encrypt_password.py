#!/usr/bin/env python3
"""A module that encrypts passwords.
"""
import bcrypt


def hash_password(password: str) -> str:
    """Hashes a password using bcrypt and returns the hashed password as a string.
    """
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def is_valid(hashed_password: str, password: str) -> bool:
    """Checks if a hashed password matches the given password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
