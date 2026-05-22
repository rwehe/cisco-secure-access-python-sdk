# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Module for generating an access token for Cisco SSE API authentication.

This module provides a function to obtain an OAuth2 access token using client credentials stored in environment variables.

Usage:
    from access_token import generate_access_token
    token = generate_access_token()

What it does:
- Reads CLIENT_ID and CLIENT_SECRET from environment variables.
- Encodes credentials in base64 and requests an access token from the Cisco SSE API.
- Returns the access token string for use in API authentication.

Requirements:
- Set CLIENT_ID and CLIENT_SECRET environment variables before use.
- Ensure all dependencies in requirements.txt are installed.

Raises:
- ValueError if required environment variables are missing.
- Exception if token generation fails.
"""

import os
import base64
from time import time
from secure_access.api.token_api import TokenApi
from typing import Optional
import dotenv


def generate_access_token(
    client_id: Optional[str] = None, client_secret: Optional[str] = None,
    save_to_file: bool = False, file_path: str = ".env"
) -> str:
    """
    Generates an OAuth2 access token for Cisco SSE API authentication.

    Args:
        client_id (Optional[str]): The client ID to use. If not provided, uses CLIENT_ID env var.
        client_secret (Optional[str]): The client secret to use. If not provided, uses CLIENT_SECRET env var.
        save_to_file (bool): Whether to save the generated token to a file. Defaults to False.
        file_path (str): The file path to save the token if save_to_file is True. Defaults to ".env".

    Returns:
        str: The access token string.

    Raises:
        ValueError: If neither parameters nor environment variables are set.
        Exception: If token generation fails.
    """
    cid = client_id or os.getenv("CLIENT_ID")
    csecret = client_secret or os.getenv("CLIENT_SECRET")
    if not cid or not csecret:
        raise ValueError(
            "CLIENT_ID and CLIENT_SECRET must be provided as arguments or set as environment variables."
        )
    token_api = TokenApi()
    base64_credentials = base64.b64encode(f"{cid}:{csecret}".encode()).decode()
    try:
        response = token_api.create_auth_token(
            grant_type="client_credentials",
            _headers={"Authorization": f"Basic {base64_credentials}"},
        )
        if save_to_file:
            save_access_token(response, file_path)
        return response.access_token
    except Exception as e:
        print(f"An error occurred while creating the access token: {e}")
        raise Exception("Failed to generate access token") from e
    
def save_access_token(response: dict, file_path: str = ".env") -> None:
    """
    Saves the access token to a file.

    Args:
        response (dict): The response containing the access token and expiration.
        file_path (str): The path to the file where the token will be saved. Defaults to '.env'.
    """
    try:
        dotenv.set_key(file_path, "ACCESS_TOKEN", str(response.access_token))
        dotenv.set_key(file_path, "EXPIRES_IN", str(response.expires_in))
        dotenv.set_key(file_path, "TIMESTAMP", str(time()))
        print(f"Access token saved to {file_path}")
    except Exception as e:
        print(f"An error occurred while saving the access token: {e}")
        raise Exception("Failed to save access token") from e
    
def is_token_expired(file_path: str = ".env") -> bool:
    """
    Checks if the access token is expired based on the saved timestamp and expiration time.

    Args:
        file_path (str): The path to the file where the token is saved. Defaults to '.env'.

    Returns:
        bool: True if the token is expired, False otherwise.
    """
    try:
        expires_in = int(dotenv.get_key(file_path, "EXPIRES_IN") or 0)
        timestamp = float(dotenv.get_key(file_path, "TIMESTAMP") or 0)
        current_time = time()
        return current_time >= timestamp + expires_in
    except Exception as e:
        print(f"An error occurred while checking token expiration: {e}")
        raise Exception("Failed to check token expiration") from e
    
def get_valid_access_token(file_path: str = ".env") -> str:
    """
    Retrieves a valid access token, generating a new one if the current token is expired.

    Args:
        file_path (str): The path to the file where the token is saved. Defaults to '.env'.

    Returns:
        str: A valid access token string.
    """
    try:
        if is_token_expired(file_path):
            print("Access token is expired. Generating a new one.")
            return generate_access_token(save_to_file=True, file_path=file_path)
        else:
            return dotenv.get_key(file_path, "ACCESS_TOKEN") or ""
    except Exception as e:
        print(f"An error occurred while retrieving the access token: {e}")
        raise Exception("Failed to retrieve access token") from e