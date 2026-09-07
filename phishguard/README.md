# PhishGuard — AI-Powered Email Threat Detection & Forensic Intelligence Platform

SIH prototype for: *AI-Powered Email Threat Detection, GeoLocation and Forensic
Intelligence Platform* (Ministry problem statement).

## What this does

You upload an email (`.eml` file) or paste email text, and PhishGuard:
1. Uses a trained ML model to judge if the *language* looks like phishing
2. Analyzes the technical headers (SPF/DKIM/DMARC, spoofed sender, relay path)
3. Looks up the sending IP's location and the domain's DNS/WHOIS reputation
4. Combines all three into one fraud risk score with a full forensic report

## Project structure

```
phishguard/
├── app.py                  <- Main dashboard (run this)
├── train_model.py          <- Trains the ML classifier
├── header_analysis.py      <- Header/SPF/DKIM/DMARC forensics
├── origin_intel.py         <- IP geolocation + domain intelligence
├── attribution_graph.py    <- Links related emails into campaigns
├── requirements.txt        <- Python libraries needed
├── data/
│   ├── generate_dataset.py <- Builds the training dataset
│   └── emails_dataset.csv  <- The generated dataset (already included)
├── models/
│   └── phishing_classifier.joblib  <- The trained model (already included)
└── sample_emails/
    ├── phishing_sample.eml                  <- Test email #1 (should score HIGH risk)
    ├── phishing_sample_2_same_campaign.eml  <- Test email #2 (shares IP with #1 -- upload both to see campaign correlation)
    └── legit_sample.eml                     <- Test email #3 (should score LOW risk)
```

## Setup — step by step

### 1. Open this folder in VS Code
File → Open Folder → select the `phishguard` folder.

### 2. Open a terminal in VS Code
`Terminal` menu → `New Terminal`

### 3. (Recommended) Create a virtual environment
This keeps these libraries separate from other Python projects on your machine.

**Windows:**
```
python -m venv venv
venv\Scripts\activate
```

**Mac/Linux:**
```
python3 -m venv venv
source venv/bin/activate
```

You'll know it worked if you see `(venv)` at the start of your terminal line.

### 4. Install the required libraries
```
pip install -r requirements.txt
```

### 5. Verify the model works (should already be trained, but let's re-train fresh on your machine to be safe)
```
python train_model.py
```
You should see something like `Test Accuracy: 100.00%` and `Model saved to models/phishing_classifier.joblib`.

### 6. IMPORTANT — test origin_intel.py with YOUR internet connection
This is the one piece I could not fully test myself (my dev sandbox has restricted
network access). Run this now:
```
python origin_intel.py
```
**Expected result:** you should see real geolocation data for `8.8.8.8` (something
like `Mountain View, United States, Google LLC`) and DNS record info for `google.com`.

- ✅ If you see real data — everything works, move to step 7.
- ⚠️ If you see errors/timeouts — your network (or a firewall/college wifi) is
  blocking these lookups. The app will still run and won't crash (I built in
  fallback handling), but geolocation/domain-age features will show "unknown."
  Tell me what error you see and I'll help troubleshoot.

### 7. Run the app
```
streamlit run app.py
```
This should automatically open a browser tab at `http://localhost:8501`. If not,
copy that URL into your browser manually.

### 8. Test it
In the app:
1. Choose "Upload .eml file"
2. Upload `sample_emails/phishing_sample.eml` → click Analyze → should show **HIGH RISK**
3. Try again with `sample_emails/legit_sample.eml` → should show **LIKELY LEGITIMATE**
4. Now also upload `sample_emails/phishing_sample_2_same_campaign.eml` → click Analyze
5. Go to the **🕸️ Campaign Correlation** tab → it should now show that emails #1 and #3
   (the two phishing ones) are linked by shared infrastructure (same sending IP),
   forming a detected "campaign" — while the legitimate email stays separate.
   This demonstrates the attribution/correlation feature from the problem statement.

## Known limitations (be upfront about these in your SIH pitch — judges respect honesty)

- The ML model is trained on a **synthetic dataset** (400 realistic examples covering
  common phishing patterns), not a massive real-world dataset. Good for a working demo;
  a production version would train on a large real dataset (e.g. public Kaggle phishing
  datasets) for stronger accuracy.
- **Origin intelligence needs internet access** to work (it calls free public services:
  ip-api.com for geolocation, public DNS, public WHOIS). No API key or payment needed.
- The **attribution graph** (linking related fraud campaigns across multiple emails) and
  **case management dashboard** from the full problem statement are the next features
  we're planning to add — good material for your "future work" slide.

## If something breaks

Copy the exact error message and send it to me — don't try to debug blind. Also tell me:
- Your OS (Windows/Mac/Linux)
- Output of `python --version` (or `python3 --version`)
- Which step you were on
