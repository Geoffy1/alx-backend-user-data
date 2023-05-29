#!/usr/bin/env python3
"""Basic authentcn mod for API.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentcn cls.
    """
    @staticmethod
    def extract_base64_authorization_header(authorization_header: str) -> str:
        """Extract Base64 part of the Authorization header
        for a Basic Authentication.
        """
        if isinstance(authorization_header, str):
            match = re.match(r'Basic\s+(.+)', authorization_header.strip())
            if match:
                return match.group(1)
        return None

    @staticmethod
    def decode_base64_authorization_header(base64_authorization_header: str) -> str:
        """Decodes a base64-encoded authorization header.
        """
        if isinstance(base64_authorization_header, str):
            try:
                res = base64.b64decode(base64_authorization_header, validate=True)
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                pass
        return None

    @staticmethod
    def extract_user_credentials(decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extract user credentials from a base64-decoded authorization
        header that uses the Basic authntcn flow.
        """
        if isinstance(decoded_base64_authorization_header, str):
            match = re.match(r'([^:]+):(.+)', decoded_base64_authorization_header.strip())
            if match:
                return match.group(1), match.group(2)
        return None, None

    @staticmethod
    def user_object_from_credentials(user_email: str, user_pwd: str) -> TypeVar('User'):
        """Retrieve user based on the user's authentication credentials.
        """
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({'email': user_email})
                if users and users[0].is_valid_password(user_pwd):
                    return users[0]
            except Exception:
                pass
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieve user from a request.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
