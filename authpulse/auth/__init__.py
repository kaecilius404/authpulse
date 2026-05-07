"""Auth package for AuthPulse."""
from authpulse.auth.authenticator import AuthSession, Authenticator
from authpulse.auth.jwt_utils import (
    extract_claims,
    is_jwt,
    make_expired_token,
    make_malformed_token,
    make_none_alg_token,
    make_role_modified_token,
    parse_jwt,
)

__all__ = [
    "AuthSession",
    "Authenticator",
    "extract_claims",
    "is_jwt",
    "make_expired_token",
    "make_malformed_token",
    "make_none_alg_token",
    "make_role_modified_token",
    "parse_jwt",
]
