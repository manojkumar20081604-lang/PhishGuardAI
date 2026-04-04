# PhishGuard Deployment on Render

## Option 1: Render (Free Tier)

### Steps:

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "PhishGuard - AI Phishing Detection"
   git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
   git push -u origin main
   ```

2. **Connect to Render**
   - Go to [render.com](https://render.com)
   - Sign up/Login with GitHub
   - Click **"New +"** → **"Web Service"**
   - Connect your GitHub repo
   - Settings:
     - **Name:** phishguard
     - **Region:** Singapore (or nearest)
     - **Branch:** main
     - **Root Directory:** (leave empty)
     - **Runtime:** Python 3
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`

3. **Environment Variables** (optional)
   - `SECRET_KEY`: any random string

4. **Deploy!** Click "Create Web Service"

---

## Option 2: Railway.app (Free Tier)

1. Create account at [railway.app](https://railway.app)
2. New Project → Deploy from GitHub
3. Select your repo
4. Railway auto-detects Python

---

## Option 3: PythonAnywhere (Free Tier)

1. Create account at [pythonanywhere.com](https://pythonanywhere.com)
2. Open Bash console
3. Clone repo:
   ```bash
   git clone https://github.com/YOUR_USERNAME/phishguard.git
   ```
4. Create virtualenv and install requirements
5. Use Flask app server (manual start)

---

## Option 4: Fly.io (Free Tier)

```bash
fly launch
fly deploy
```

---

## Database Note

For free deployment, the app runs in **demo mode** (no MySQL persistence). History won't save between restarts.

For full features with MySQL:
- Use **Render's PostgreSQL** addon (free tier available)
- Update `database.py` with PostgreSQL connection

---

## Troubleshooting

**Import Errors?**
- Make sure all dependencies are in `requirements.txt`
- Check Python version (3.8+)

**Static Files Not Loading?**
- Ensure `static/` folder is in root
- Check path in `app.py` for templates folder

**Port Errors?**
- Use `$PORT` environment variable (Render sets this)
- Don't hardcode port 5000
