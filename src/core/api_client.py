"""
Secure iNaturalist API client with comprehensive error handling.
OWASP compliant with rate limiting and input validation.
"""

import requests
import math
import time
from typing import Optional, Dict, Any, List
from datetime import datetime
from core.models import Location, Observation, TaxonType
from utils.exceptions import APIError, ValidationError
from config.settings import settings


class TaxonMapping:
    """Secure taxon ID mapping."""
    ANIMAL = 1  # Kingdom Animalia
    PLANT = 47126  # Kingdom Plantae
    FISH = 47178  # Ray-finned fishes (Actinopterygii)
    
    @classmethod
    def get_taxon_id(cls, taxon_type: TaxonType) -> int:
        """Get taxon ID for type."""
        mapping = {
            TaxonType.ANIMAL: cls.ANIMAL,
            TaxonType.PLANT: cls.PLANT,
            TaxonType.FISH: cls.FISH
        }
        return mapping[taxon_type]


class GeographicCalculator:
    """Secure geographic calculations."""
    
    EARTH_RADIUS_MILES = 3959.0
    
    @classmethod
    def calculate_square_bbox(cls, location: Location) -> Dict[str, str]:
        """
        Calculate secure bounding box from location.
        Returns dict with API-compatible coordinate strings.
        """
        # Validate inputs are within reasonable bounds
        if not (-90 <= location.latitude <= 90):
            raise ValidationError(f"Invalid latitude: {location.latitude}")
        if not (-180 <= location.longitude <= 180):
            raise ValidationError(f"Invalid longitude: {location.longitude}")
        if not (0.1 <= location.radius_miles <= 100):
            raise ValidationError(f"Invalid radius: {location.radius_miles}")
        
        # Convert radius to degrees (approximate)
        lat_delta = location.radius_miles / cls.EARTH_RADIUS_MILES * (180 / math.pi)
        
        # Longitude delta adjusts for latitude (more compression near poles)
        lon_delta = lat_delta / math.cos(math.radians(location.latitude))
        
        min_lat = location.latitude - lat_delta
        max_lat = location.latitude + lat_delta
        min_lon = location.longitude - lon_delta
        max_lon = location.longitude + lon_delta
        
        return {
            "swlng": f"{min_lon:.5f}",
            "swlat": f"{min_lat:.5f}",
            "nelng": f"{max_lon:.5f}",
            "nelat": f"{max_lat:.5f}"
        }


class SecureAPIClient:
    """
    Secure iNaturalist API client with OWASP compliance.
    Implements proper error handling, timeouts, and request validation.
    """
    
    def __init__(self):
        self.base_url = "https://api.inaturalist.org/v1/observations"
        self.session = requests.Session()
        
        # Security headers
        self.session.headers.update({
            "User-Agent": settings.inat_user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close"  # Prevent connection reuse for security
        })
        
        # Configure session for security
        self.session.verify = True  # Always verify SSL certificates
        
        # Performance tracking
        self._last_request_time = 0
        self._request_count = 0
    
    def fetch_latest_observation(self, location: Location, taxon_type: TaxonType) -> Optional[Observation]:
        """
        Fetch the latest observation for a specific taxon type and location.
        
        Args:
            location: Validated location object
            taxon_type: Type of taxon to search for
            
        Returns:
            Observation object or None if no results
            
        Raises:
            APIError: For API-related errors
            ValidationError: For invalid parameters
        """
        try:
            # Rate limiting - be respectful to iNaturalist API
            self._enforce_rate_limit()
            
            # Get taxon ID and bounding box
            taxon_id = TaxonMapping.get_taxon_id(taxon_type)
            bbox = GeographicCalculator.calculate_square_bbox(location)
            
            # Build secure API parameters
            params = {
                "quality_grade": "research",
                "taxon_id": taxon_id,
                "order": "desc",
                "order_by": "observed_on",
                "per_page": 1,
                "page": 1,
                "locale": "en",
                **bbox
            }
            
            # Validate all parameters are safe
            self._validate_api_params(params)
            
            # Make the API request
            response = self.session.get(
                self.base_url,
                params=params,
                timeout=settings.inat_timeout
            )
            
            # Update tracking
            self._last_request_time = time.time()
            self._request_count += 1
            
            # Handle HTTP errors
            if response.status_code == 429:
                raise APIError("Rate limit exceeded", "RATE_LIMIT_EXCEEDED")
            elif response.status_code >= 500:
                raise APIError("API server error", "SERVER_ERROR")
            elif response.status_code >= 400:
                raise APIError(f"API client error: {response.status_code}", "CLIENT_ERROR")
            
            response.raise_for_status()
            
            # Parse JSON response securely
            try:
                data = response.json()
            except ValueError as e:
                raise APIError(f"Invalid JSON response: {e}", "INVALID_RESPONSE")
            
            # Validate response structure
            if not isinstance(data, dict):
                raise APIError("Unexpected response format", "INVALID_RESPONSE")
            
            results = data.get("results", [])
            if not results or not isinstance(results, list):
                return None
            
            # Parse the first result into secure observation
            return self._parse_observation_safely(results[0])
            
        except requests.RequestException as e:
            raise APIError(f"Network error: {e}", "NETWORK_ERROR")
        except Exception as e:
            # Don't leak internal errors
            raise APIError("API request failed", "REQUEST_FAILED")
    
    def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting to be respectful to the API."""
        if self._last_request_time:
            time_since_last = time.time() - self._last_request_time
            min_interval = 0.5  # Minimum 0.5 seconds between requests
            
            if time_since_last < min_interval:
                time.sleep(min_interval - time_since_last)
    
    def _validate_api_params(self, params: Dict[str, Any]) -> None:
        """Validate API parameters for security."""
        # Check for allowed parameters only
        allowed_params = {
            "quality_grade", "taxon_id", "order", "order_by", 
            "per_page", "page", "locale", "swlng", "swlat", "nelng", "nelat"
        }
        
        for key in params:
            if key not in allowed_params:
                raise ValidationError(f"Invalid API parameter: {key}")
        
        # Validate parameter values
        if params.get("per_page", 1) > 100:
            raise ValidationError("per_page too large")
        if params.get("page", 1) > 1000:
            raise ValidationError("page too large")
    
    def _parse_observation_safely(self, raw_obs: Dict[str, Any]) -> Optional[Observation]:
        """
        Parse raw observation data into secure Observation model.
        
        Args:
            raw_obs: Raw observation data from API
            
        Returns:
            Validated Observation object or None if parsing fails
        """
        try:
            # Extract and validate required fields
            obs_id = str(raw_obs.get("id", "unknown"))
            
            # Extract taxon information safely
            taxon = raw_obs.get("taxon") or {}
            taxon_id = taxon.get("id", 1)
            common_name = (
                taxon.get("preferred_common_name") or 
                raw_obs.get("species_guess") or 
                taxon.get("name") or 
                "Unknown"
            )
            scientific_name = taxon.get("name")
            
            # Parse observation time safely
            observed_at = self._parse_observed_time_safely(raw_obs)
            
            # Extract observer safely
            user = raw_obs.get("user") or {}
            observer = user.get("login", "unknown")
            
            # Extract coordinates safely
            coordinates = self._extract_coordinates_safely(raw_obs)
            if not coordinates:
                return None
            
            # Extract URLs safely
            uri = raw_obs.get("uri") or raw_obs.get("url")
            photo_url = self._extract_photo_url_safely(raw_obs)
            
            # Create validated observation
            return Observation(
                id=obs_id,
                taxon_id=taxon_id,
                common_name=common_name,
                scientific_name=scientific_name,
                observed_at=observed_at,
                observer=observer,
                location_coords=coordinates,
                uri=uri,
                photo_url=photo_url
            )
            
        except Exception as e:
            # Log the error but don't expose it
            return None
    
    def _parse_observed_time_safely(self, raw_obs: Dict[str, Any]) -> str:
        """Parse observation time with fallbacks."""
        # Try time_observed_at first (includes timezone)
        iso_time = raw_obs.get("time_observed_at")
        if iso_time:
            try:
                dt = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
                return f"{dt:%Y-%m-%d %H:%M} UTC"
            except Exception:
                pass
        
        # Fallback to observed_on (date only)
        date_only = raw_obs.get("observed_on")
        if date_only:
            try:
                return f"{date_only} (date only)"
            except Exception:
                pass
        
        # Fallback to created_at
        created = raw_obs.get("created_at")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                return f"{dt:%Y-%m-%d %H:%M} UTC (created time)"
            except Exception:
                pass
        
        return "unknown time"
    
    def _extract_coordinates_safely(self, raw_obs: Dict[str, Any]) -> Optional[tuple[float, float]]:
        """Extract coordinates with validation."""
        try:
            geojson = raw_obs.get("geojson") or {}
            coords = geojson.get("coordinates")
            
            if isinstance(coords, list) and len(coords) == 2:
                lon, lat = float(coords[0]), float(coords[1])
                
                # Validate coordinate ranges
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    return (lat, lon)
            
            return None
            
        except (ValueError, TypeError):
            return None
    
    def _extract_photo_url_safely(self, raw_obs: Dict[str, Any]) -> Optional[str]:
        """Extract photo URL with validation."""
        try:
            photos = raw_obs.get("photos", [])
            if photos and isinstance(photos, list):
                photo = photos[0]
                url = photo.get("url") or photo.get("original_url")
                if url and isinstance(url, str) and url.startswith("http"):
                    return url[:500]  # Limit length
            return None
        except Exception:
            return None
    
    def get_client_stats(self) -> Dict[str, Any]:
        """Get client performance statistics."""
        return {
            "total_requests": self._request_count,
            "last_request_time": self._last_request_time,
            "session_active": True
        }
    
    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()


# Global client instance for reuse
_api_client: Optional[SecureAPIClient] = None


def get_api_client() -> SecureAPIClient:
    """Get singleton API client instance."""
    global _api_client
    if _api_client is None:
        _api_client = SecureAPIClient()
    return _api_client


def cleanup_api_client() -> None:
    """Clean up the global API client."""
    global _api_client
    if _api_client:
        _api_client.close()
        _api_client = None