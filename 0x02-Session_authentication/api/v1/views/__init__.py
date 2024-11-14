#!/usr/bin/env python3
""" DocDocDocDocDocDoc
"""
from flask import Blueprint

app_views = Blueprint("app_views", __name__, url_prefix="/api/v1")

from api.v1.views.index import *
from api.v1.views.users import *

# Load user data from file (assuming this is necessary for your application)
User.load_from_file()

# Import the session authentication views at the end to avoid circular imports
from api.v1.views.session_auth import *
