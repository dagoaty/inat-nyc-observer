"""
Security-focused configuration management.
Environment-based settings with validation.
"""

from pydantic import BaseSettings, Field, validator
import os
from typing import Optional


class Settings(BaseSettings):
    """Application settings with security validation."""
    
    # iNaturalist API Configuration
    inat_base_url: str = Field(
        "https://api.inaturalist.org/v1/observations",
        regex=r'^https://[a-zA-Z0-9.-]+/.*$'
    )
    inat_timeout: int = Field(10, ge=1, le=30)
    inat_user_agent: str = Field("iNat-Observer/2.0")
    
    # Default Location (NYC Times Square)
    default_latitude: float = Field(40.7580, ge=-90, le=90)
    default_longitude: float = Field(-73.9855, ge=-180, le=180)
    default_radius_miles: float = Field(30.0, ge=0.1, le=100)
    
    # Taxon IDs (readonly)
    taxon_animal: int = Field(1, ge=1)
    taxon_plant: int = Field(47126, ge=1)
    taxon_fish: int = Field(47178, ge=1)
    
    # Security Settings
    max_requests_per_hour: int = Field(1000, ge=1, le=10000)
    rate_limit_window_seconds: int = Field(3600, ge=60, le=86400)
    max_response_size_mb: int = Field(10, ge=1, le=50)
    request_timeout_seconds: int = Field(30, ge=5, le=60)
    
    # Logging Configuration
    log_level: str = Field("INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    enable_debug_logging: bool = Field(False)
    
    # Feature Flags
    enable_request_logging: bool = Field(True)
    enable_metrics: bool = Field(True)
    enable_cors: bool = Field(False)
    
    # AWS Configuration
    aws_region: str = Field("us-east-1", regex="^[a-z0-9-]+$")
    
    @validator('enable_debug_logging')
    def no_debug_in_production(cls, v, values):
        """Prevent debug logging in production environments."""
        environment = os.getenv('ENVIRONMENT', '').lower()
        if v and environment in ['production', 'prod']:
            raise ValueError("Debug logging not allowed in production")
        return v
    
    @validator('inat_user_agent')
    def validate_user_agent(cls, v):
        """Ensure user agent follows proper format."""
        if not v or len(v) > 200:
            raise ValueError("User agent must be 1-200 characters")
        # Remove potentially dangerous characters
        import re
        sanitized = re.sub(r'[<>"\']', '', v)
        return sanitized
    
    class Config:
        env_prefix = "INAT_"
        case_sensitive = False
        # Don't read from .env files in production for security
        env_file = None if os.getenv('ENVIRONMENT') == 'production' else '.env'


# Global settings instance
settings = Settings()


# Security constants (not configurable)
class SecurityConstants:
    """Security-related constants that should not be configurable."""
    
    # Maximum values to prevent resource exhaustion
    MAX_CONCURRENT_REQUESTS = 10
    MAX_REQUEST_SIZE_BYTES = 1024 * 1024  # 1MB
    MAX_RESPONSE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
    
    # Rate limiting defaults
    DEFAULT_RATE_LIMIT = 100  # requests per hour per IP
    BURST_RATE_LIMIT = 10    # requests per minute per IP
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none';"
    }
    
    # Allowed parameters for API requests (whitelist approach)
    ALLOWED_API_PARAMS = {
        'quality_grade', 'taxon_id', 'swlng', 'swlat', 
        'nelng', 'nelat', 'order', 'order_by', 
        'per_page', 'page', 'locale'
    }
    
    # Regex patterns for validation
    COORDINATE_PATTERN = r'^-?(?:(?:180(?:\.0+)?)|(?:(?:1[0-7]\d)|(?:[1-9]?\d))(?:\.\d+)?)$'
    REQUEST_ID_PATTERN = r'^[a-zA-Z0-9_-]{8,32}$'