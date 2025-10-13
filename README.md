# inat_test

Small test script that fetches observations from the iNaturalist API.

How to run

1. Create and activate a virtual environment (recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

2. Run the script:

```powershell
python .\inat_test.py
```

Notes
- The script uses the `requests` package and needs network access to reach the iNaturalist API.
- Edit the `place_id`, `taxon_id`, or date range in the `if __name__ == "__main__"` block to change the query.
