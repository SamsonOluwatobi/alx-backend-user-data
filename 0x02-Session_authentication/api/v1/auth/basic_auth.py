#!/usr/bin/env python3
"""module containing the class BasicAuth that inherits from Auth"""
from api.v1.auth.auth import Auth
from typing import TypeVar, Tuple
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """Class for Basic Authentication methods"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic
        Authentication

        Args:
            authorization_header (str): The authorization header to extract the
            Base64 part from

        Returns:
            str: The Base64 part of the header if present, otherwise None
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """
        Decodes the Base64 part of the Authorization header for Basic
        Authentication

        Args:
            base64_authorization_header (str): The Base64 string to decode

        Returns:
            str: The decoded value as a UTF-8 string if successful,
            otherwise None
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        method that returns returns the user email and password from the Base64
        decoded value.

        Args:
            decoded_base64_authorization_heade (str): Base64 decoded string

            Returns:
                 tuple: user email and password or (None, None) if invalid
                 input
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        usr_email, usr_password = \
            decoded_base64_authorization_header.split(':', 1)
        return usr_email, usr_password

    def user_object_from_credentials(self, user_email: str, user_pwd:
                                     str) -> TypeVar('User'):
        """
        Returns the User instance based on the provided email and password.

        Args:
            user_email (str): User email
            user_pwd (str): User password

        Returns:
            User: User instance if credentials are valid, None otherwise
        """
        # Check if user_email or user_pwd is None or not a string
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        # Search for the user by email using the User class method `search`
        try:
            user_list = User.search({'email': user_email})
            if not user_list or user_list == []:
                return None
            for user_eml in user_list:
                if user_eml.is_valid_password(user_pwd):
                    return user_eml
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the user from a request.

        Args:
            request: The request object containing the authorization header.

        Returns:
            User: The User instance based on the provided credentials,
            None if invalid.
        """
        # Extract the authorization header from the request
        authorization_header = self.authorization_header(request)

        # Extract the Base64 part of the authorization header
        base64_authorization_header = self.extract_base64_authorization_header(
            authorization_header)

        # Decode the Base64 authorization header
        decoded_authorization_header = self.decode_base64_authorization_header(
            base64_authorization_header)

        # Extract user email and password from the decoded authorization header
        user_email, user_password = self.extract_user_credentials(
            decoded_authorization_header)

        # Retrieve the User instance based on the extracted credentials
        return self.user_object_from_credentials(
            user_email, user_password)
