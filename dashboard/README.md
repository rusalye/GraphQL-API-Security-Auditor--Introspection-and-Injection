# Dashboard Demo

This standalone dashboard is designed to showcase the GraphQL security middleware in a live demo.

## What it does

- Pulls live enforcement metrics from the middleware's `/stats` endpoint
- Displays total requests, blocked requests, forwarded requests, and block rate
- Shows rule-level and source IP summaries
- Alerts immediately when attacks are blocked
- Provides a demo narrative for presenting the system

## How to use

### Option 1: Open locally

1. Open `dashboard/index.html` in your browser.
2. Set the stats endpoint to `http://localhost:8080/stats` (or your middleware host).
3. The dashboard will refresh automatically every 4 seconds.

### Option 2: Serve via a local static server

```bash
cd dashboard
python -m http.server 8000
```

Then browse to `http://localhost:8000`.

## Notes

- The dashboard uses the middleware's CORS policy, so it can be opened from a browser without modifying the middleware.
- If your middleware is running on a different host or port, update the API endpoint field accordingly.
- This is a standalone demo asset and does not require changes to existing project files.
