import requests
from datetime import datetime
from zoneinfo import ZoneInfo

BASE = "https://api.inaturalist.org/v1/observations"
HEADERS = {"User-Agent": "NYC-Latest-Trio/1.0 (contact: you@example.com)"}

# NYC bounding box (WGS84): minLon,minLat,maxLon,maxLat
NYC_BBOX = "-74.25559,40.49612,-73.70001,40.91553"

# iNaturalist taxon IDs
TAXON_ANIMALIA = 1          # Animals (Kingdom Animalia)
TAXON_PLANTAE = 47126       # Plants (Kingdom Plantae)
TAXON_ACTINOPTERYGII = 47178  # Ray-finned fishes (covers most fish you’ll see)

LOCAL_TZ = ZoneInfo("America/New_York")

def fetch_latest_for_taxon(taxon_id: int):
    """Return the single most recent observation for a given taxon_id within NYC."""
    params = {
        "verifiable": "true",
        "quality_grade": "research,needs_id",
        "taxon_id": taxon_id,
        "bbox": NYC_BBOX,
        "order": "desc",
        "order_by": "observed_on",   # sort by when it was SEEN
        "per_page": 1,
        "page": 1,
        "locale": "en",
    }
    r = requests.get(BASE, params=params, headers=HEADERS, timeout=30)
    r.raise_for_status()
    results = r.json().get("results", [])
    return results[0] if results else None

def parse_observed_time(obs):
    """
    Parse the observation's time (preferring time_observed_at which includes a TZ offset),
    then convert to America/New_York. Return a nicely formatted string.
    """
    iso = obs.get("time_observed_at")  # e.g., '2025-10-12T14:07:22-04:00'
    if iso:
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            local = dt.astimezone(LOCAL_TZ)
            # Example: 2025-10-12 02:07 PM EDT (UTC-04:00)
            return f"{local:%Y-%m-%d %I:%M %p} {local.tzname()} (UTC{local.utcoffset().total_seconds()/3600:+.0f}:00)"
        except Exception:
            pass

    # Fallbacks: observed_on (date only) or created_at
    date_only = obs.get("observed_on")
    if date_only:
        try:
            # assume noon local if no time provided
            dt = datetime.fromisoformat(date_only)  # yyyy-mm-dd
            local = dt.replace(tzinfo=LOCAL_TZ)
            return f"{local:%Y-%m-%d 12:00 PM} {local.tzname()} (assumed noon)"
        except Exception:
            pass

    created = obs.get("created_at")
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            local = dt.astimezone(LOCAL_TZ)
            return f"{local:%Y-%m-%d %I:%M %p} {local.tzname()} (created time)"
        except Exception:
            pass

    return "unknown time"

def summarize(obs, label):
    if not obs:
        print(f"\n{label}: No recent observation found in NYC.")
        return
    taxon = obs.get("taxon") or {}
    common = taxon.get("preferred_common_name") or obs.get("species_guess") or taxon.get("name") or "Unknown"
    sci = taxon.get("name")
    user = obs.get("user", {}).get("login", "unknown")
    when = parse_observed_time(obs)
    uri = obs.get("uri") or obs.get("url")
    coords = obs.get("geojson", {}).get("coordinates")
    latlon = f"{coords[1]:.5f}, {coords[0]:.5f}" if isinstance(coords, list) and len(coords) == 2 else "n/a"
    photo = None
    if obs.get("photos"):
        photo = obs["photos"][0].get("url") or obs["photos"][0].get("original_url")

    print(f"\n{label}")
    print("-" * len(label))
    print(f"Common name : {common}")
    if sci:
        print(f"Scientific  : {sci}")
    print(f"Observed at : {when}")
    print(f"Observer    : @{user}")
    print(f"Location    : {latlon}")
    if uri:
        print(f"Observation : {uri}")
    if photo:
        print(f"Photo       : {photo}")

def main():
    try:
        animal = fetch_latest_for_taxon(TAXON_ANIMALIA)
        plant = fetch_latest_for_taxon(TAXON_PLANTAE)
        fish  = fetch_latest_for_taxon(TAXON_ACTINOPTERYGII)
    except requests.RequestException as e:
        print(f"Network/API error: {e}")
        return

    summarize(animal, "Most recent ANIMAL in NYC")
    summarize(plant,  "Most recent PLANT in NYC")
    summarize(fish,   "Most recent FISH in NYC")

if __name__ == "__main__":
    main()
