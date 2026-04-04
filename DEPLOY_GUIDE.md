# PhishGuard AI — GitHub + Render Deployment Guide

## Files You Got (replace in your project folder)
| File | What Changed |
|------|-------------|
| `main.js` | Fixed stray `}}` bug that broke all JS |
| `style.css` | Fixed chatbot CSS (was invisible) |
| `app.py` | SECRET_KEY from env var, CORS fixed |
| `requirements.txt` | Removed tensorflow/pymysql, added Pillow |
| `runtime.txt` | Now correctly says `python-3.11.0` |
| `render.yaml` | New — Render auto-config |
| `Procfile` | New — tells Render how to start |
| `build.sh` | New — build script |
| `gitignore.txt` | Rename this to `.gitignore` in your folder |
| `phishguard_questions.js` | Fixed ES module export bug |

---

## STEP 1 — Prepare Your Local Folder

Replace files in your project folder, then:

```bash
# Rename gitignore.txt → .gitignore
# On Windows:
ren gitignore.txt .gitignore

# Create models folder (empty, so git tracks it)
mkdir models
echo "" > models/.gitkeep
```

---

## STEP 2 — Push to GitHub

```bash
# Open terminal in your project folder

git init
git add .
git commit -m "PhishGuard AI - production ready"

# Go to github.com → New Repository
# Name it: phishguard-ai
# Keep it Public, no README

git remote add origin https://github.com/YOUR_USERNAME/phishguard-ai.git
git branch -M main
git push -u origin main
```

---

## STEP 3 — Deploy on Render

1. Go to **render.com** → Sign up with GitHub
2. Click **New +** → **Web Service**
3. Connect your **phishguard-ai** repository
4. Fill in settings:

| Setting | Value |
|---------|-------|
| Name | phishguard-ai |
| Region | Singapore (closest to Chennai) |
| Branch | main |
| Runtime | Python 3 |
| Build Command | `pip install -r requirements.txt && python train_model.py` |
| Start Command | `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120` |
| Instance Type | Free |

5. Under **Environment Variables** → Add:

| Key | Value |
|-----|-------|
| `SECRET_KEY` | any long random string like `phishguard2024xyzABC!@#secretkey` |

6. Click **Create Web Service**
7. Wait ~5 minutes for build to finish
8. Your app will be live at: `https://phishguard-ai.onrender.com`

---

## STEP 4 — Test After Deploy

Check these URLs work:
- `https://your-app.onrender.com/` → Main dashboard
- `https://your-app.onrender.com/login` → Login page  
- `https://your-app.onrender.com/api/health` → Should return `{"status":"healthy"}`

---

## Common Errors & Fixes

### Build fails with "No module named X"
→ Add that module to `requirements.txt` and push again

### App crashes on start
→ Check Render logs → Usually a missing env var or import error

### Login doesn't persist
→ Make sure `SECRET_KEY` env var is set in Render dashboard

### Models not found warning
→ Normal on first boot — `train_model.py` runs during build and creates them

### Free tier sleeps after 15 mins
→ Normal on Render free tier. First request after sleep takes ~30 sec to wake up.
→ To avoid this, upgrade to Starter ($7/month) or use UptimeRobot to ping it every 10 mins

---

## After Deploy — Share Your Project

Your app URL will be: `https://phishguard-ai.onrender.com`

Add this to your GitHub README and science expo presentation!
