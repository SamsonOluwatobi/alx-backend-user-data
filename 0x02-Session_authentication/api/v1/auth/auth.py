#!/usr/bin/env python3
"""module to manage the the API authentication."""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """class to manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Define which routes don't need authentication"""
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        # Nomalize path by ensuring it ends with a slash
        if not path.endswith('/'):
            path += '/'

        for excluded_path in excluded_paths:
            # Normalize excluded_path by ensuring it ends with a slash
            if not excluded_path.endswith('/'):
                excluded_path += '/'

            if path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Returns the value of the 'Authorization' header from the request
        if it exists.
        """
        if request is None:
            return None

        if request.headers.get('Authorization') is None:
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None - request will be the Flask request object"""
        return None

    def session_cookie(self, request=None):
        """
        returns a cookie value from a request

        Args:
            request (str): default set to None

        Return: Return None if request is None also return value of the cookie
            named _my_session_id from request
        """
        if request is None:
            return None
        session_name = getenv('SESSION_NAME')

        return request.cookies.get(session_name)
