"""
Security-aware custom exceptions with proper error handling.
"""

from typing import Optional, Dict, Any


class INatObserverError(Exception):
    """Base exception for iNat Observer with security considerations."""
    
    def __init__(self, message: str, error_code: str = "UNKNOWN", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details
        }


class ValidationError(INatObserverError):
    """Input validation errors - safe to expose to users."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[str] = None):
        super().__init__(message, "VALIDATION_ERROR")
        self.field = field
        self.value = value
        if field:
            self.details["field"] = field
        # Don't include actual value in details for security


class SecurityViolationError(INatObserverError):
    """Security violations - should be logged but not exposed."""
    
    def __init__(self, message: str, violation_type: str, source_ip: Optional[str] = None):
        super().__init__(message, "SECURITY_VIOLATION")
        self.violation_type = violation_type
        self.source_ip = source_ip
        self.details.update({
            "violation_type": violation_type,
            "source_ip": source_ip
        })
    
    def get_public_message(self) -> str:
        """Return safe message for public consumption."""
        return "Request blocked for security reasons"


class RateLimitExceededError(SecurityViolationError):
    """Rate limiting violations."""
    
    def __init__(self, message: str = "Rate limit exceeded", source_ip: Optional[str] = None, limit: Optional[int] = None):
        super().__init__(message, "RATE_LIMIT", source_ip)
        if limit:
            self.details["limit"] = limit
    
    def get_public_message(self) -> str:
        return "Too many requests. Please try again later."


class INatAPIError(INatObserverError):
    """iNaturalist API related errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message, "API_ERROR")
        self.status_code = status_code
        self.response_body = response_body
        if status_code:
            self.details["status_code"] = status_code
        # Don't include response body in details for security
    
    def get_public_message(self) -> str:
        """Return safe message for public consumption."""
        if self.status_code == 429:
            return "External API rate limit exceeded. Please try again later."
        elif self.status_code and 500 <= self.status_code < 600:
            return "External service temporarily unavailable. Please try again later."
        else:
            return "Unable to fetch observations at this time."


class GeometryError(INatObserverError):
    """Geometry calculation errors."""
    
    def __init__(self, message: str, latitude: Optional[float] = None, longitude: Optional[float] = None, radius: Optional[float] = None):
        super().__init__(message, "GEOMETRY_ERROR")
        self.latitude = latitude
        self.longitude = longitude
        self.radius = radius
        # Include coordinates in details for debugging (they're not sensitive)
        if latitude is not None:
            self.details["latitude"] = latitude
        if longitude is not None:
            self.details["longitude"] = longitude
        if radius is not None:
            self.details["radius"] = radius


class ConfigurationError(INatObserverError):
    """Configuration and setup errors."""
    
    def __init__(self, message: str, config_key: Optional[str] = None):
        super().__init__(message, "CONFIG_ERROR")
        self.config_key = config_key
        if config_key:
            self.details["config_key"] = config_key
    
    def get_public_message(self) -> str:
        return "Service configuration error. Please try again later."


class ResourceExhaustionError(SecurityViolationError):
    """Resource exhaustion attacks or legitimate overload."""
    
    def __init__(self, message: str, resource_type: str, limit: Optional[int] = None):
        super().__init__(message, "RESOURCE_EXHAUSTION")
        self.resource_type = resource_type
        self.details.update({
            "resource_type": resource_type,
            "limit": limit
        })
    
    def get_public_message(self) -> str:
        return "Request size or complexity exceeds limits. Please simplify your request."


# Exception handler utility
# Aliases for compatibility
APIError = INatAPIError


class SecurityAwareExceptionHandler:
    """Utility for handling exceptions with security considerations."""
    
    @staticmethod
    def is_safe_to_expose(exception: Exception) -> bool:
        """Determine if an exception is safe to expose to users."""
        safe_exceptions = (ValidationError, RateLimitExceededError)
        return isinstance(exception, safe_exceptions)
    
    @staticmethod
    def get_public_error_response(exception: Exception, request_id: str) -> Dict[str, Any]:
        """Generate safe error response for public consumption."""
        if isinstance(exception, INatObserverError):
            if hasattr(exception, 'get_public_message'):
                message = exception.get_public_message()
            elif SecurityAwareExceptionHandler.is_safe_to_expose(exception):
                message = exception.message
            else:
                message = "An error occurred while processing your request"
        else:
            # Unknown exception - never expose details
            message = "An unexpected error occurred"
        
        return {
            "error": message,
            "request_id": request_id,
            "error_code": getattr(exception, 'error_code', 'UNKNOWN')
        }
    
    @staticmethod
    def should_alert_security_team(exception: Exception) -> bool:
        """Determine if security team should be alerted."""
        return isinstance(exception, SecurityViolationError)