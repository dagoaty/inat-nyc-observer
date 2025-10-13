import requests
from datetime import datetime

# iNaturalist API endpoint
BASE = "https://api.inaturalist.org/v1/observations"

# NYC bounding box (WGS84): minLon,minLat,maxLon,maxLat
NYC_BBOX = "-74.25559,40.49612,-73.70001,40.91553"

# Animalia taxon_id on iNaturalist
ANIMALIA_TAXON_ID = 1

HEADERS = {
    "User-Agent": "NYC-Animal-Latest/1.0 (contact: you@example.com)"
}

def get_latest_animal_in_nyc():
    params = {
        "verifiable": "true",
        "quality_grade": "research,needs_id",  # include verifiable observations
        "taxon_id": ANIMALIA_TAXON_ID,
        "bbox": NYC_BBOX,
        "order": "desc",
        "order_by": "observed_on",          # sort by when it was SEEN
        "per_page": 1,
        "page": 1,
        "locale": "en"
    }

    r = requests.get(BASE, params=params, headers=HEADERS, timeout=30)
    r.raise_for_status()
    data = r.json()

    results = data.get("results", [])
    if not results:
        return None

    return results[0]

def fmt_when(obs):
    # Prefer observed_on_string; fallback to created_at details
    when = obs.get("observed_on_details", {})
    y, m, d = when.get("year"), when.get("month"), when.get("day")
    if y and m and d:
        try:
            return datetime(y, m, d).strftime("%Y-%m-%d")
        except Exception:
            pass
    # fallback
    return obs.get("observed_on", obs.get("created_at", "unknown"))

def main():
    try:
        obs = get_latest_animal_in_nyc()
    except requests.HTTPError as e:
        print(f"HTTP error from iNaturalist: {e}")
        return
    except requests.RequestException as e:
        print(f"Network error: {e}")
        return

    if not obs:
        print("No recent animal observations found in NYC.")
        return

    # Pull out a few friendly fields
    species = (
        obs.get("taxon", {}).get("preferred_common_name")
        or obs.get("species_guess")
        or obs.get("taxon", {}).get("name")
        or "Unknown species"
    )
    sci_name = obs.get("taxon", {}).get("name")
    user = obs.get("user", {}).get("login", "unknown")
    observed_on = fmt_when(obs)
    uri = obs.get("uri") or obs.get("observation_uri") or obs.get("url")

    # Coordinates
    lat = obs.get("geojson", {}).get("coordinates", [None, None])
    lon, lat = (lat[0], lat[1]) if isinstance(lat, list) and len(lat) == 2 else (None, None)

    # First photo (if available)
    photos = obs.get("photos", [])
    photo_url = None
    if photos:
        # Try a medium-size url if present, else fallback to original
        photo_url = photos[0].get("url") or photos[0].get("original_url")

    print("\nMost recent animal observed in NYC")
    print("---------------------------------")
    print(f"Common name : {species}")
    if sci_name:
        print(f"Scientific  : {sci_name}")
    print(f"Observed on : {observed_on}")
    print(f"Observer    : @{user}")
    if lat is not None and lon is not None:
        print(f"Location    : {lat:.5f}, {lon:.5f}")
    if uri:
        print(f"Observation : {uri}")
    if photo_url:
        print(f"Photo       : {photo_url}")

if __name__ == "__main__":
    main()
