"""
Comprehensive input validation and sanitization.
OWASP-compliant protection against injection attacks.
"""

import re
import json
import time
from typing import Dict, Any, Optional, Union
from urllib.parse import unquote
from core.models import Location, SecureRequest
from utils.exceptions import ValidationError, SecurityViolationError
from config.settings import settings, SecurityConstants


class RequestValidator:
    """
    Comprehensive request validator implementing OWASP security guidelines.
    Protects against injection attacks, malformed input, and suspicious patterns.
    """
    
    def __init__(self):
        # Compile regex patterns for performance
        self.sql_injection_pattern = re.compile(
            r'(\b(select|insert|update|delete|drop|create|alter|exec|union|script|javascript|vbscript)\b|'
            r'[;\'"\\]|--|\|\||&&|<script|</script>|<iframe|</iframe>)',
            re.IGNORECASE
        )
        
        self.xss_pattern = re.compile(
            r'(<script[^>]*>.*?</script>|<iframe[^>]*>.*?</iframe>|'
            r'javascript:|vbscript:|data:text/html|<object|<embed|<applet)',
            re.IGNORECASE | re.DOTALL
        )
        
        self.path_traversal_pattern = re.compile(
            r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|%252e%252e%252f)',
            re.IGNORECASE
        )
        
        self.command_injection_pattern = re.compile(
            r'(\||;|&|`|\$\(|\${|<\(|>\()',
            re.IGNORECASE
        )
    
    def validate_lambda_event(self, event: Dict[str, Any], request_id: str) -> Dict[str, Any]:
        """
        Validate and sanitize AWS Lambda event.
        
        Args:
            event: Raw Lambda event
            request_id: Request ID for logging
            
        Returns:
            Validated and sanitized event
            
        Raises:
            ValidationError: For invalid input
            SecurityViolationError: For security violations
        """
        try:
            # Create sanitized copy
            sanitized_event = {}
            
            # Extract and validate location parameters
            location_data = self._extract_location_data(event)
            validated_location = self._validate_location(location_data)
            
            # Create secure request object
            secure_request = SecureRequest(
                location=validated_location,
                request_id=request_id,
                timestamp=time.time(),
                source_ip=self._extract_source_ip(event),
                user_agent=self._extract_user_agent(event)
            )
            
            # Add validated data to sanitized event
            sanitized_event.update({
                'location': validated_location.dict(),
                'request_metadata': {
                    'request_id': request_id,
                    'timestamp': secure_request.timestamp,
                    'source_ip': secure_request.source_ip
                }
            })
            
            return sanitized_event
            
        except ValidationError:
            raise  # Re-raise validation errors
        except Exception as e:
            raise SecurityViolationError(
                f"Input validation failed: {str(e)}",
                "VALIDATION_FAILURE"
            )
    
    def _extract_location_data(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract location data from various sources in the event."""
        location_data = {}
        
        # Check query string parameters
        query_params = event.get('queryStringParameters') or {}
        if query_params:
            location_data.update({
                'latitude': query_params.get('lat'),
                'longitude': query_params.get('lon'),
                'radius_miles': query_params.get('radius')
            })
        
        # Check path parameters (from rawPath)
        raw_path = event.get('rawPath', '')
        if raw_path and raw_path != '/':
            path_data = self._parse_path_parameters(raw_path)
            location_data.update(path_data)
        
        # Check POST body
        body = event.get('body')
        if body:
            try:
                body_data = json.loads(body) if isinstance(body, str) else body
                if isinstance(body_data, dict):
                    location_data.update({
                        'latitude': body_data.get('lat'),
                        'longitude': body_data.get('lon'),
                        'radius_miles': body_data.get('radius')
                    })
            except json.JSONDecodeError:
                raise ValidationError("Invalid JSON in request body")
        
        # Use defaults for missing values
        return {
            'latitude': location_data.get('latitude') or settings.default_latitude,
            'longitude': location_data.get('longitude') or settings.default_longitude,
            'radius_miles': location_data.get('radius_miles') or settings.default_radius_miles
        }
    
    def _parse_path_parameters(self, raw_path: str) -> Dict[str, Any]:
        """Parse path parameters in format /key/value/key/value."""
        path_data = {}
        
        # Remove leading/trailing slashes and split
        path_parts = raw_path.strip('/').split('/')
        
        # Process key/value pairs
        for i in range(0, len(path_parts) - 1, 2):
            key = path_parts[i].lower()
            value = path_parts[i + 1]
            
            # URL decode
            try:
                value = unquote(value)
            except Exception:
                continue  # Skip invalid URL encoding
            
            # Map to expected parameter names
            if key == 'lat':
                path_data['latitude'] = value
            elif key == 'lon':
                path_data['longitude'] = value
            elif key == 'radius':
                path_data['radius_miles'] = value
        
        return path_data
    
    def _validate_location(self, location_data: Dict[str, Any]) -> Location:
        """Validate location data using Pydantic model."""
        try:
            # Pre-validate and sanitize each field
            sanitized_data = {}
            
            for key, value in location_data.items():
                if value is not None:
                    # Check for security violations
                    self._check_security_patterns(str(value), key)
                    
                    # Sanitize and convert
                    sanitized_value = self._sanitize_numeric_input(value, key)
                    sanitized_data[key] = sanitized_value
            
            # Create and validate Location model
            return Location(**sanitized_data)
            
        except ValueError as e:
            raise ValidationError(f"Invalid location data: {str(e)}")
    
    def _sanitize_numeric_input(self, value: Union[str, int, float], field_name: str) -> float:
        """Sanitize and convert numeric input."""
        if isinstance(value, (int, float)):
            return float(value)
        
        if isinstance(value, str):
            # Remove any non-numeric characters except decimal point and minus
            sanitized = re.sub(r'[^\d.-]', '', value)
            
            if not sanitized or sanitized in ['-', '.', '-.']:
                raise ValidationError(f"Invalid {field_name}: empty or invalid format")
            
            try:
                return float(sanitized)
            except ValueError:
                raise ValidationError(f"Invalid {field_name}: cannot convert to number")
        
        raise ValidationError(f"Invalid {field_name}: unsupported type")
    
    def _check_security_patterns(self, value: str, field_name: str) -> None:
        """Check for security violation patterns in input."""
        
        # Check for SQL injection patterns
        if self.sql_injection_pattern.search(value):
            raise SecurityViolationError(
                f"SQL injection attempt detected in {field_name}",
                "SQL_INJECTION"
            )
        
        # Check for XSS patterns
        if self.xss_pattern.search(value):
            raise SecurityViolationError(
                f"XSS attempt detected in {field_name}",
                "XSS_ATTEMPT"
            )
        
        # Check for path traversal
        if self.path_traversal_pattern.search(value):
            raise SecurityViolationError(
                f"Path traversal attempt detected in {field_name}",
                "PATH_TRAVERSAL"
            )
        
        # Check for command injection
        if self.command_injection_pattern.search(value):
            raise SecurityViolationError(
                f"Command injection attempt detected in {field_name}",
                "COMMAND_INJECTION"
            )
        
        # Check for suspicious length
        if len(value) > 1000:  # Reasonable limit for coordinate strings
            raise SecurityViolationError(
                f"Suspiciously long input in {field_name}",
                "OVERSIZED_INPUT"
            )
    
    def _extract_source_ip(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract and validate source IP address."""
        # Check X-Forwarded-For header first
        headers = event.get('headers', {})
        forwarded_for = headers.get('X-Forwarded-For', headers.get('x-forwarded-for'))
        
        if forwarded_for:
            # Take the first IP (leftmost) from the chain
            ip = forwarded_for.split(',')[0].strip()
            if self._is_valid_ip(ip):
                return ip
        
        # Fallback to request context
        request_context = event.get('requestContext', {})
        identity = request_context.get('identity', {})
        source_ip = identity.get('sourceIp')
        
        if source_ip and self._is_valid_ip(source_ip):
            return source_ip
        
        return None
    
    def _extract_user_agent(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract and sanitize user agent."""
        headers = event.get('headers', {})
        user_agent = headers.get('User-Agent', headers.get('user-agent'))
        
        if user_agent:
            # Sanitize user agent
            sanitized = re.sub(r'[<>"\']', '', str(user_agent))
            return sanitized[:500] if sanitized else None
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        # IPv4 validation
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ipv4_pattern, ip):
            # Additional validation for valid ranges
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # IPv6 validation (basic)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, ip):
            return True
        
        return False


class ResponseValidator:
    """Validator for outgoing responses to prevent data leakage."""
    
    @staticmethod
    def sanitize_response_body(body: str) -> str:
        """Sanitize response body to prevent information leakage."""
        if not body:
            return body
        
        # Remove any potential script tags or suspicious content
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', body, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<iframe[^>]*>.*?</iframe>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove any internal server information
        sanitized = re.sub(r'(server|host|internal|debug|stacktrace|error|exception):\s*[^\n\r]*', 
                          '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    @staticmethod
    def validate_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize response headers."""
        safe_headers = {}
        
        for key, value in headers.items():
            # Sanitize header values
            safe_value = re.sub(r'[<>"\'\r\n]', '', str(value))
            
            # Only include safe headers
            if key.lower() not in ['server', 'x-powered-by', 'x-aspnet-version']:
                safe_headers[key] = safe_value
        
        return safe_headers