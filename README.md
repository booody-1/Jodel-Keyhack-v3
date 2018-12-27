# r2HmacExtractor

# Install on Windows

0. Use package managers
   - [Chocolatey](https://chocolatey.org/) for programs
   - [scoop](https://scoop.sh/) for dev tools
1. Install requirements
   - `scoop install radare2`
   - `choco install nodejs`
   - `choco install python3`
1. Create virtual env
   - `py -3 -m venv venv`
1. Activate virtualenv
   - `venv\Scripts\activate`
1. Install python deps
   - `pip install -r requirements.txt`
1. Build frontend
   - `npm ci`
   - `npm run build:prod`
1. Start backend
   - `python3 backend/main.py`

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
