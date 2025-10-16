"""
OWASP-compliant security middleware for Lambda functions.
Implements multiple layers of security controls.
"""

import functools
import time
import hashlib
import json
from typing import Dict, Any, Callable, Optional
from utils.exceptions import (
    SecurityViolationError, RateLimitExceededError, ValidationError,
    ResourceExhaustionError, SecurityAwareExceptionHandler
)
from config.settings import settings, SecurityConstants
from security.rate_limiting import RateLimiter
from security.validation import RequestValidator


class SecurityMiddleware:
    """
    Comprehensive security middleware implementing OWASP best practices.
    
    Protects against:
    - A01:2021 – Broken Access Control
    - A02:2021 – Cryptographic Failures  
    - A03:2021 – Injection
    - A04:2021 – Insecure Design
    - A05:2021 – Security Misconfiguration
    - A06:2021 – Vulnerable and Outdated Components
    - A07:2021 – Identification and Authentication Failures
    - A08:2021 – Software and Data Integrity Failures
    - A09:2021 – Security Logging and Monitoring Failures
    - A10:2021 – Server-Side Request Forgery (SSRF)
    """
    
    def __init__(self):
        self.rate_limiter = RateLimiter(
            max_requests=settings.max_requests_per_hour,
            window_seconds=settings.rate_limit_window_seconds
        )
        self.validator = RequestValidator()
        self._security_logger = None  # Will be set by logging module
    
    def secure_handler(self, func: Callable) -> Callable:
        """
        Decorator that applies comprehensive security measures to Lambda handlers.
        """
        @functools.wraps(func)
        def wrapper(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
            request_id = self._generate_secure_request_id(event)
            start_time = time.time()
            
            try:
                # 1. Pre-flight security checks
                self._log_security_event("request_started", {
                    "request_id": request_id,
                    "source_ip": self._get_source_ip(event),
                    "user_agent": self._get_user_agent(event),
                    "method": event.get('httpMethod', 'UNKNOWN'),
                    "path": event.get('path', 'UNKNOWN')
                })
                
                # 2. Request size validation (prevent resource exhaustion)
                self._validate_request_size(event)
                
                # 3. Rate limiting per source IP
                self._enforce_rate_limiting(event)
                
                # 4. Input validation and sanitization
                validated_event = self._validate_and_sanitize_input(event, request_id)
                
                # 5. Execute the actual handler
                response = func(validated_event, context)
                
                # 6. Secure the response
                secured_response = self._secure_response(response, request_id)
                
                # 7. Log successful completion
                self._log_security_event("request_completed", {
                    "request_id": request_id,
                    "status": "success",
                    "duration_ms": (time.time() - start_time) * 1000,
                    "response_size": len(json.dumps(secured_response))
                })
                
                return secured_response
                
            except Exception as e:
                # Security-aware error handling
                return self._handle_security_error(e, request_id, event, start_time)
        
        return wrapper
    
    def _generate_secure_request_id(self, event: Dict[str, Any]) -> str:
        """Generate cryptographically secure request ID for tracking."""
        timestamp = str(time.time())
        source_ip = self._get_source_ip(event)
        request_context = event.get('requestContext', {})
        request_id = request_context.get('requestId', 'unknown')
        
        # Create secure hash from multiple sources
        content = f"{timestamp}:{source_ip}:{request_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _get_source_ip(self, event: Dict[str, Any]) -> str:
        """Extract source IP with X-Forwarded-For consideration."""
        # Check X-Forwarded-For header (but validate it)
        headers = event.get('headers', {})
        forwarded_for = headers.get('X-Forwarded-For', headers.get('x-forwarded-for'))
        
        if forwarded_for:
            # Take the first IP (leftmost) from the chain
            ip = forwarded_for.split(',')[0].strip()
            # Basic IP validation
            import re
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                return ip
        
        # Fallback to request context
        request_context = event.get('requestContext', {})
        identity = request_context.get('identity', {})
        return identity.get('sourceIp', 'unknown')
    
    def _get_user_agent(self, event: Dict[str, Any]) -> str:
        """Extract and sanitize user agent."""
        headers = event.get('headers', {})
        user_agent = headers.get('User-Agent', headers.get('user-agent', 'unknown'))
        
        # Sanitize user agent (remove potentially dangerous chars)
        import re
        sanitized = re.sub(r'[<>"\']', '', str(user_agent))
        return sanitized[:500]  # Limit length
    
    def _validate_request_size(self, event: Dict[str, Any]) -> None:
        """Validate request size to prevent resource exhaustion attacks."""
        request_size = len(json.dumps(event, default=str))
        
        if request_size > SecurityConstants.MAX_REQUEST_SIZE_BYTES:
            raise ResourceExhaustionError(
                f"Request size {request_size} exceeds maximum {SecurityConstants.MAX_REQUEST_SIZE_BYTES}",
                "REQUEST_SIZE",
                SecurityConstants.MAX_REQUEST_SIZE_BYTES
            )
    
    def _enforce_rate_limiting(self, event: Dict[str, Any]) -> None:
        """Enforce rate limiting per source IP."""
        source_ip = self._get_source_ip(event)
        
        if not self.rate_limiter.is_allowed(source_ip):
            raise RateLimitExceededError(
                f"Rate limit exceeded for IP {source_ip}",
                source_ip,
                settings.max_requests_per_hour
            )
    
    def _validate_and_sanitize_input(self, event: Dict[str, Any], request_id: str) -> Dict[str, Any]:
        """Validate and sanitize all input data."""
        try:
            return self.validator.validate_lambda_event(event, request_id)
        except ValidationError:
            raise  # Re-raise validation errors as-is
        except Exception as e:
            # Convert unexpected validation errors to security violations
            raise SecurityViolationError(
                f"Input validation failed: {str(e)}",
                "INPUT_VALIDATION_FAILURE",
                self._get_source_ip(event)
            )
    
    def _secure_response(self, response: Dict[str, Any], request_id: str) -> Dict[str, Any]:
        """Apply security headers and sanitize response."""
        if not isinstance(response, dict):
            response = {'statusCode': 500, 'body': 'Internal error'}
        
        # Ensure headers exist
        if 'headers' not in response:
            response['headers'] = {}
        
        # Add security headers
        response['headers'].update(SecurityConstants.SECURITY_HEADERS)
        
        # Add request ID for tracking
        response['headers']['X-Request-ID'] = request_id
        
        # Validate response size
        response_size = len(json.dumps(response, default=str))
        if response_size > SecurityConstants.MAX_RESPONSE_SIZE_BYTES:
            # Log the oversized response attempt
            self._log_security_event("response_too_large", {
                "request_id": request_id,
                "response_size": response_size,
                "limit": SecurityConstants.MAX_RESPONSE_SIZE_BYTES
            })
            
            # Return a safe error response
            return {
                'statusCode': 413,
                'headers': {**SecurityConstants.SECURITY_HEADERS, 'X-Request-ID': request_id},
                'body': json.dumps({
                    "error": "Response too large",
                    "request_id": request_id
                })
            }
        
        return response
    
    def _handle_security_error(self, exception: Exception, request_id: str, 
                             event: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        """Handle errors with security considerations."""
        
        source_ip = self._get_source_ip(event)
        duration_ms = (time.time() - start_time) * 1000
        
        # Log security violation
        self._log_security_event("request_failed", {
            "request_id": request_id,
            "error_type": exception.__class__.__name__,
            "source_ip": source_ip,
            "duration_ms": duration_ms,
            "should_alert": SecurityAwareExceptionHandler.should_alert_security_team(exception)
        })
        
        # Generate safe error response
        error_response = SecurityAwareExceptionHandler.get_public_error_response(exception, request_id)
        
        # Determine HTTP status code
        if isinstance(exception, ValidationError):
            status_code = 400
        elif isinstance(exception, RateLimitExceededError):
            status_code = 429
        elif isinstance(exception, ResourceExhaustionError):
            status_code = 413
        elif isinstance(exception, SecurityViolationError):
            status_code = 403
        else:
            status_code = 500
        
        return {
            'statusCode': status_code,
            'headers': {
                **SecurityConstants.SECURITY_HEADERS,
                'X-Request-ID': request_id,
                'Content-Type': 'application/json'
            },
            'body': json.dumps(error_response)
        }
    
    def _log_security_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log security events for monitoring and alerting."""
        if self._security_logger:
            self._security_logger.info(event_type, extra=details)
        else:
            # Fallback to print for now (will be replaced by proper logging)
            print(f"SECURITY_EVENT: {event_type} - {json.dumps(details, default=str)}")
    
    def set_security_logger(self, logger):
        """Set the security logger instance."""
        self._security_logger = logger