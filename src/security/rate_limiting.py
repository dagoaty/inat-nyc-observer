"""
Rate limiting implementation for Lambda functions.
Prevents abuse and resource exhaustion attacks.
"""

import time
import hashlib
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
from threading import Lock
from config.settings import SecurityConstants


class RateLimiter:
    """
    In-memory rate limiter with sliding window implementation.
    Suitable for Lambda functions with proper memory management.
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in the time window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, float] = {}  # IP -> block_until_timestamp
        self._lock = Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # Clean up every 5 minutes
    
    def is_allowed(self, identifier: str, burst_check: bool = True) -> bool:
        """
        Check if request is allowed for the given identifier.
        
        Args:
            identifier: Usually IP address or user ID
            burst_check: Whether to also check burst rate limiting
            
        Returns:
            True if request is allowed, False otherwise
        """
        with self._lock:
            now = time.time()
            
            # Periodic cleanup to prevent memory leaks
            self._cleanup_if_needed(now)
            
            # Check if IP is temporarily blocked
            if self._is_temporarily_blocked(identifier, now):
                return False
            
            # Clean old requests for this identifier
            self._clean_old_requests(identifier, now)
            
            # Check burst rate (last minute)
            if burst_check and not self._check_burst_rate(identifier, now):
                self._temporary_block(identifier, now, duration=60)  # Block for 1 minute
                return False
            
            # Check main rate limit
            if not self._check_main_rate_limit(identifier):
                self._temporary_block(identifier, now, duration=300)  # Block for 5 minutes
                return False
            
            # Request is allowed - record it
            self.requests[identifier].append(now)
            return True
    
    def _is_temporarily_blocked(self, identifier: str, now: float) -> bool:
        """Check if identifier is temporarily blocked."""
        if identifier in self.blocked_ips:
            if now < self.blocked_ips[identifier]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[identifier]
        return False
    
    def _clean_old_requests(self, identifier: str, now: float) -> None:
        """Remove requests outside the time window."""
        window_start = now - self.window_seconds
        request_times = self.requests[identifier]
        
        while request_times and request_times[0] < window_start:
            request_times.popleft()
    
    def _check_burst_rate(self, identifier: str, now: float) -> bool:
        """Check burst rate limiting (requests per minute)."""
        burst_window_start = now - 60  # Last minute
        recent_requests = sum(1 for req_time in self.requests[identifier] 
                            if req_time >= burst_window_start)
        
        return recent_requests < SecurityConstants.BURST_RATE_LIMIT
    
    def _check_main_rate_limit(self, identifier: str) -> bool:
        """Check main rate limit."""
        return len(self.requests[identifier]) < self.max_requests
    
    def _temporary_block(self, identifier: str, now: float, duration: int) -> None:
        """Temporarily block an identifier."""
        self.blocked_ips[identifier] = now + duration
    
    def _cleanup_if_needed(self, now: float) -> None:
        """Periodic cleanup to prevent memory leaks."""
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup_old_data(now)
            self._last_cleanup = now
    
    def _cleanup_old_data(self, now: float) -> None:
        """Clean up old data to prevent memory leaks."""
        # Clean up old request records
        identifiers_to_remove = []
        window_start = now - self.window_seconds
        
        for identifier, request_times in self.requests.items():
            # Remove old requests
            while request_times and request_times[0] < window_start:
                request_times.popleft()
            
            # Remove identifiers with no recent requests
            if not request_times:
                identifiers_to_remove.append(identifier)
        
        for identifier in identifiers_to_remove:
            del self.requests[identifier]
        
        # Clean up expired blocks
        expired_blocks = [ip for ip, block_until in self.blocked_ips.items() 
                         if now >= block_until]
        for ip in expired_blocks:
            del self.blocked_ips[ip]
    
    def get_rate_limit_status(self, identifier: str) -> Dict[str, any]:
        """Get current rate limit status for identifier."""
        with self._lock:
            now = time.time()
            self._clean_old_requests(identifier, now)
            
            current_requests = len(self.requests[identifier])
            remaining = max(0, self.max_requests - current_requests)
            
            # Calculate reset time (when oldest request expires)
            reset_time = None
            if self.requests[identifier]:
                oldest_request = self.requests[identifier][0]
                reset_time = oldest_request + self.window_seconds
            
            return {
                "limit": self.max_requests,
                "remaining": remaining,
                "reset_time": reset_time,
                "window_seconds": self.window_seconds,
                "is_blocked": self._is_temporarily_blocked(identifier, now)
            }


class DistributedRateLimiter:
    """
    Rate limiter for distributed environments using external storage.
    For future implementation with Redis or DynamoDB.
    """
    
    def __init__(self, storage_backend, max_requests: int = 100, window_seconds: int = 3600):
        """
        Initialize distributed rate limiter.
        
        Args:
            storage_backend: External storage backend (Redis, DynamoDB, etc.)
            max_requests: Maximum requests allowed in the time window
            window_seconds: Time window in seconds
        """
        self.storage = storage_backend
        self.max_requests = max_requests
        self.window_seconds = window_seconds
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed using distributed storage.
        To be implemented when external storage is available.
        """
        # Implementation would use external storage
        # For now, fall back to in-memory limiter
        return True


class RateLimitDecorator:
    """Decorator for applying rate limiting to specific functions."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600, 
                 key_func: Optional[callable] = None):
        """
        Initialize rate limit decorator.
        
        Args:
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            key_func: Function to extract rate limiting key from arguments
        """
        self.rate_limiter = RateLimiter(max_requests, window_seconds)
        self.key_func = key_func or (lambda *args, **kwargs: "default")
    
    def __call__(self, func):
        """Apply rate limiting to the decorated function."""
        def wrapper(*args, **kwargs):
            # Extract rate limiting key
            key = self.key_func(*args, **kwargs)
            
            # Check rate limit
            if not self.rate_limiter.is_allowed(key):
                from utils.exceptions import RateLimitExceededError
                raise RateLimitExceededError(f"Rate limit exceeded for key: {key}")
            
            # Execute function
            return func(*args, **kwargs)
        
        return wrapper


# Utility functions for rate limiting

def create_ip_based_key(event: Dict[str, any]) -> str:
    """Create rate limiting key based on IP address."""
    # Extract IP from Lambda event
    request_context = event.get('requestContext', {})
    identity = request_context.get('identity', {})
    source_ip = identity.get('sourceIp', 'unknown')
    
    # Hash the IP for privacy (optional)
    return hashlib.sha256(source_ip.encode()).hexdigest()[:16]


def create_user_based_key(user_id: str) -> str:
    """Create rate limiting key based on user ID."""
    return f"user:{user_id}"


def create_composite_key(ip: str, user_id: Optional[str] = None) -> str:
    """Create composite rate limiting key."""
    if user_id:
        return f"composite:{ip}:{user_id}"
    return f"ip:{ip}"