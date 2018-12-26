# r2HmacExtractor

Needed to run:

- Python 3
- radare2 (needs to be on path)

```bash
# Install virtualenv
python3 -m venv venv
py -3 -m venv venv # on Windows

# Go into the virtual env
. venv/bin/activate
venv\Scripts\activate # on Windows

# Install dependencies
pip install -r requirements.txt

# Run
python3 backend/main.py
```

# Install on macOS

1. Install requirements
   - `brew install radare2`
   - `brew install nodejs`
   - `brew install python3`
2. Create virtual env
   - `python3 -m venv venv`
3. Activate virtualenv
   - `. venv/bin/activate`
4. Install python deps
   - `pip install -r requirements.txt`
5. Build frontend
   - `npm ci`
   - `npm run build:prod`
6. Start backend
   - `python3 backend/main.py`
