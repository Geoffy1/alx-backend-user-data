#!/usr/bin/env python3
"""Authentication module for the API.
"""
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class.
    """
    @staticmethod
    def require_auth(path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication.
        """
        if path and excluded_paths:
            for exclusion_path in map(str.strip, excluded_paths):
                if exclusion_path.endswith('*'):
                    pattern = '{}.*'.format(exclusion_path[:-1])
                elif exclusion_path.endswith('/'):
                    pattern = '{}/*'.format(exclusion_path[:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    @staticmethod
    def authorization_header(request=None) -> str:
        """Gets the authorization header field from the request.
        """
        if request:
            return request.headers.get('Authorization', None)
        return None

    @staticmethod
    def current_user(request=None) -> TypeVar('User'):
        """Gets the current user from the request.
        """
        return None
