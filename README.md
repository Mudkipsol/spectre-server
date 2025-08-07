# Spectre License Server

Lightweight Flask backend for issuing and validating license keys.

## Endpoints

- `POST /generate_trial` — creates trial key for new machine + user
- `POST /check_license` — returns license status + spoof count
- `POST /increment_spoof` — increments spoof usage count

## To Run Locally

```bash
pip install -r requirements.txt
python app.py
```

## Deploy to Render (Free)

1. Go to https://render.com
2. Create a new Web Service
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `python app.py`