"""
Secure data models with comprehensive validation.
OWASP compliant input validation and sanitization.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from decimal import Decimal, InvalidOperation
import re
from enum import Enum


class TaxonType(str, Enum):
    """Enumeration of supported taxon types."""
    ANIMAL = "animal"
    PLANT = "plant"
    FISH = "fish"


class Location(BaseModel):
    """Secure location model with strict validation."""
    
    latitude: float = Field(
        ..., 
        ge=-90, 
        le=90, 
        description="Latitude in decimal degrees"
    )
    longitude: float = Field(
        ..., 
        ge=-180, 
        le=180, 
        description="Longitude in decimal degrees"
    )
    radius_miles: float = Field(
        ..., 
        ge=0.1, 
        le=100, 
        description="Search radius in miles (max 100 for performance)"
    )
    
    @validator('latitude', 'longitude', 'radius_miles', pre=True)
    def sanitize_numeric_input(cls, v):
        """Prevent injection attacks through numeric fields."""
        if isinstance(v, str):
            # Remove any non-numeric characters except decimal point and minus
            sanitized = re.sub(r'[^\d.-]', '', str(v))
            if not sanitized or sanitized in ['-', '.', '-.']:
                raise ValueError(f"Invalid numeric value: {v}")
            try:
                return float(Decimal(sanitized))
            except (InvalidOperation, ValueError):
                raise ValueError(f"Invalid numeric value: {v}")
        return v
    
    @validator('radius_miles')
    def validate_reasonable_radius(cls, v):
        """Prevent resource exhaustion attacks."""
        if v > 100:
            raise ValueError("Radius too large - maximum 100 miles allowed for performance")
        if v < 0.1:
            raise ValueError("Radius too small - minimum 0.1 miles required")
        return v
    
    def to_description(self) -> str:
        """Generate human-readable location description."""
        return f"within {self.radius_miles} miles of {self.latitude:.4f}, {self.longitude:.4f}"


class Observation(BaseModel):
    """Secure observation model with sanitized data."""
    
    id: str = Field(..., max_length=50, regex=r'^[a-zA-Z0-9_-]+$')
    taxon_id: int = Field(..., ge=1, le=999999999)
    common_name: Optional[str] = Field(None, max_length=200)
    scientific_name: Optional[str] = Field(None, max_length=200)
    observed_at: str = Field(..., max_length=50)
    observer: str = Field(..., max_length=100)
    location_coords: tuple[float, float]
    uri: Optional[str] = Field(None, max_length=500)
    photo_url: Optional[str] = Field(None, max_length=500)
    
    @validator('common_name', 'scientific_name', 'observer', pre=True)
    def sanitize_text_fields(cls, v):
        """Sanitize text fields to prevent XSS."""
        if v is None:
            return v
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', str(v))
        # Limit length to prevent buffer overflow
        return sanitized[:200] if sanitized else None
    
    @validator('uri', 'photo_url', pre=True)
    def validate_urls(cls, v):
        """Validate and sanitize URLs."""
        if v is None:
            return v
        
        url_str = str(v)
        # Basic URL validation - must start with http/https
        if not re.match(r'^https?://', url_str):
            return None
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'\s]', '', url_str)
        return sanitized[:500] if sanitized else None
    
    @validator('location_coords', pre=True)
    def validate_coordinates(cls, v):
        """Validate coordinate tuple."""
        if not isinstance(v, (list, tuple)) or len(v) != 2:
            raise ValueError("Coordinates must be a tuple/list of two numbers")
        
        lat, lon = float(v[0]), float(v[1])
        if not (-90 <= lat <= 90):
            raise ValueError(f"Invalid latitude: {lat}")
        if not (-180 <= lon <= 180):
            raise ValueError(f"Invalid longitude: {lon}")
        
        return (lat, lon)


class ObservationSet(BaseModel):
    """Container for the three observation types."""
    
    animal: Optional[Observation] = None
    plant: Optional[Observation] = None
    fish: Optional[Observation] = None
    location: Location
    request_id: str = Field(..., max_length=32, regex=r'^[a-zA-Z0-9_-]+$')
    timestamp: float = Field(..., ge=0)
    
    class Config:
        # Prevent mass assignment attacks
        extra = 'forbid'
        # Validate assignment to prevent mutation attacks
        validate_assignment = True


class SecureRequest(BaseModel):
    """Secure request wrapper with metadata for security logging."""
    
    location: Location
    request_id: str = Field(..., max_length=32, regex=r'^[a-zA-Z0-9_-]+$')
    timestamp: float = Field(..., ge=0)
    source_ip: Optional[str] = Field(
        None, 
        regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    )
    user_agent: Optional[str] = Field(None, max_length=500)
    
    @validator('user_agent', pre=True)
    def sanitize_user_agent(cls, v):
        """Sanitize user agent string."""
        if v is None:
            return v
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', str(v))
        return sanitized[:500] if sanitized else None
    
    class Config:
        extra = 'forbid'
        validate_assignment = True


class ErrorResponse(BaseModel):
    """Standardized error response model."""
    
    error: str = Field(..., max_length=200)
    request_id: str = Field(..., max_length=32)
    timestamp: float = Field(...)
    
    @validator('error', pre=True)
    def sanitize_error_message(cls, v):
        """Sanitize error messages to prevent information leakage."""
        if not v:
            return "Unknown error"
        
        # Remove potentially sensitive information
        sanitized = re.sub(r'[<>"\']', '', str(v))
        # Generic error messages for security
        if any(keyword in sanitized.lower() for keyword in ['sql', 'database', 'connection', 'internal']):
            return "Internal processing error"
        
        return sanitized[:200]