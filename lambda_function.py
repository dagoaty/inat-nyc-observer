"""
Secure AWS Lambda handler using the refactored security-first architecture.
OWASP compliant with comprehensive security controls.
"""

import json
import time
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from security.middleware import SecurityMiddleware
from core.api_client import get_api_client, cleanup_api_client
from core.models import TaxonType, ObservationSet
from utils.exceptions import APIError, SecurityAwareExceptionHandler


# Initialize security middleware
security_middleware = SecurityMiddleware()


@security_middleware.secure_handler
def lambda_handler(event, context):
    """
    Secure AWS Lambda handler for iNaturalist observations.
    
    The security middleware has already:
    - Validated and sanitized all input
    - Applied rate limiting
    - Added security headers
    - Generated secure request ID
    
    The event now contains:
    - location: Validated Location object data
    - request_metadata: Security tracking info
    """
    
    try:
        # Extract validated location from security middleware
        location_data = event['location']
        request_id = event['request_metadata']['request_id']
        
        # Get API client
        api_client = get_api_client()
        
        # Create location object from validated data
        from core.models import Location
        location = Location(**location_data)
        
        # Fetch observations for all three taxon types
        animal_obs = api_client.fetch_latest_observation(location, TaxonType.ANIMAL)
        plant_obs = api_client.fetch_latest_observation(location, TaxonType.PLANT)
        fish_obs = api_client.fetch_latest_observation(location, TaxonType.FISH)
        
        # Create observation set
        observation_set = ObservationSet(
            animal=animal_obs,
            plant=plant_obs,
            fish=fish_obs,
            location=location,
            request_id=request_id,
            timestamp=time.time()
        )
        
        # Format response in the original text format
        response_body = format_observations_response(observation_set)
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': response_body
        }
        
    except APIError as e:
        # API errors are safe to expose (already sanitized)
        return {
            'statusCode': 503,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'error': str(e),
                'request_id': event.get('request_metadata', {}).get('request_id', 'unknown'),
                'type': 'api_error'
            })
        }
    
    except Exception as e:
        # All other exceptions are handled by security middleware
        # This should rarely be reached due to middleware error handling
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'error': 'Internal processing error',
                'request_id': event.get('request_metadata', {}).get('request_id', 'unknown')
            })
        }


def format_observations_response(obs_set: ObservationSet) -> str:
    """
    Format observation set into the original text response format.
    Maintains backward compatibility with existing clients.
    """
    
    location_desc = obs_set.location.to_description()
    sections = []
    
    # Format animal section
    sections.append(format_single_observation(
        obs_set.animal, 
        f"Most recent ANIMAL {location_desc}"
    ))
    
    # Format plant section
    sections.append(format_single_observation(
        obs_set.plant, 
        f"Most recent PLANT {location_desc}"
    ))
    
    # Format fish section
    sections.append(format_single_observation(
        obs_set.fish, 
        f"Most recent FISH {location_desc}"
    ))
    
    return "\n\n".join(sections)


def format_single_observation(observation, title: str) -> str:
    """Format a single observation in the original text format."""
    
    if not observation:
        return f"{title}\n{'-' * len(title)}\nNo recent observation found."
    
    lines = [
        title,
        "=" * 60,
        f"Common name : {observation.common_name}"
    ]
    
    if observation.scientific_name:
        lines.append(f"Scientific  : {observation.scientific_name}")
    
    lines.extend([
        f"Observed at : {observation.observed_at}",
        f"Observer    : @{observation.observer}",
        f"Location    : {observation.location_coords[0]:.5f}, {observation.location_coords[1]:.5f}"
    ])
    
    if observation.uri:
        lines.append(f"Observation : {observation.uri}")
    
    if observation.photo_url:
        lines.append(f"Photo       : {observation.photo_url}")
    
    return "\n".join(lines)


def lambda_cleanup():
    """Clean up resources when Lambda container is being destroyed."""
    cleanup_api_client()


# For backwards compatibility and testing
def handler(event, context):
    """Alias for lambda_handler for compatibility."""
    return lambda_handler(event, context)