"""Detection rule package. Rule logic lives in dedicated modules."""

from app.rules.authentication import AUTHENTICATION_RULES, AuthenticationRule

__all__ = ["AUTHENTICATION_RULES", "AuthenticationRule"]
