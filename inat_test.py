import requests
import json
import time

BASE = "https://api.inaturalist.org/v1/observations"
HEADERS = {"User-Agent": "LocalTest/1.0 (contact: you@example.com)"}


def fetch_inaturalist(place_id=None, taxon_id=None, d1=None, d2=None, max_pages=1):
    params = {
        "verifiable": "true",
        "order": "desc",
        "order_by": "created_at",
        "per_page": 50,
    }
    if place_id:
        params["place_id"] = place_id
    if taxon_id:
        params["taxon_id"] = taxon_id
    if d1:
        params["d1"] = d1
    if d2:
        params["d2"] = d2

    results = []
    for page in range(1, max_pages + 1):
        params["page"] = page
        try:
            r = requests.get(BASE, params=params, headers=HEADERS, timeout=30)
            r.raise_for_status()
        except requests.exceptions.RequestException:
            # On error, return whatever we collected so far
            return results

        try:
            data = r.json()
        except ValueError:
            return results

        obs = data.get("results", [])
        if not obs:
            break
        results.extend(obs)
        time.sleep(1)

    return results


if __name__ == "__main__":
    # Example: birds (taxon_id=3) in Berlin (place_id=97394)
    results = fetch_inaturalist(
        place_id=97394, taxon_id=3, d1="2025-09-01", d2="2025-10-01", max_pages=1
    )
    print(f"Fetched {len(results)} observations")
    # Display first 5 observations pretty-printed
    print(json.dumps(results[:5], indent=2))

    # Save full results to a JSON file
    out_path = "inat_results.json"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Saved full results to {out_path}")
    except OSError as exc:
        print(f"Failed to save results to {out_path}: {exc}")
