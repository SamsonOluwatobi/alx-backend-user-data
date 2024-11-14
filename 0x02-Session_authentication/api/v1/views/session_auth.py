#!/usr/bin/env python3
"""
Module for handling user authentication views in the API.
This module includes endpoints for login and logout functionalities
using session authentication.
"""

import os
from api.v1.views import app_views
from models.user import User
from flask import jsonify, request, abort


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_auth():
    """
    Handles the user login and session creation.
    This endpoint receives the user's email and password,
    validates them, and if the credentials are correct, creates a new
    session for the user.

    Returns:
        Response: JSON response with the user's data and a session
        cookie if successful.
        Response: JSON response with an error message and appropriate
        status code if not.
    """
    email = request.form.get('email')
    pwd = request.form.get('password')

    # Check if email is provided
    if not email or email == '':
        return jsonify({"error": "email missing"}), 400

    # Check if password is provided
    if not pwd or pwd == '':
        return jsonify({"error": "password missing"}), 400

    # Search for users with the provided email
    user = User.search({"email": email})

    # If no user is found, return an error
    if not user or user == []:
        return jsonify({"error": "no user found for this email"}), 404

    # Validate password for each user found
    for each_usr in user:
        if each_usr.is_valid_password(pwd):
            # Importing auth module here to avoid circular import issues
            from api.v1.app import auth
            session_id = auth.create_session(each_usr.id)
            response = jsonify(each_usr.to_json())
            session_name = os.getenv('SESSION_NAME')
            response.set_cookie(session_name, session_id)
            return response

    # If password is incorrect, return an error
    return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """
    Handles the user logout and session destruction.
    This endpoint destroys the current session if a valid session exists.

    Returns:
        Response: Empty JSON response with status code 200 if successful.
        Response: Abort with status code 404 if no session is found or
        destruction fails.
    """
    # Importing auth module here to avoid circular import issues
    from api.v1.app import auth

    # Destroy the session and return appropriate response
    if auth.destroy_session(request):
        return jsonify({}), 200
    abort(404)
