#!/usr/bin/env bash
# Provision the detector venv. Idempotent; run from the project root.
#   ./setup.sh            # build venv from scratch
#   ./setup.sh --with-coincurve   # same + signing support (needs gcc/cmake/linux headers)
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ required")'

[ -d venv ] || "$PY" -m venv venv
./venv/bin/pip install -q --upgrade pip

# tronpy's only hard dependency that has no binary wheel on every platform is coincurve
# (secp256k1). It is needed for key signing, NOT for reading contracts. This MVP runs
# read-only, so we install tronpy from a local copy with coincurve made optional.
if [ "${1:-}" = "--with-coincurve" ]; then
  ./venv/bin/pip install -q tronpy==0.6.2 python-dotenv "telethon>=1.36"
else
  VENDOR=vendor/tronpy-src
  if [ ! -d "$VENDOR" ]; then
    mkdir -p vendor && cd vendor
    curl -sL -o tronpy.tar.gz \
      "$(curl -s https://pypi.org/pypi/tronpy/0.6.2/json \
         | python3 -c 'import json,sys;print([f["url"] for f in json.load(sys.stdin)["urls"] if f["packagetype"]=="sdist"][0])')"
    tar xzf tronpy.tar.gz && mv tronpy-0.6.2 tronpy-src && rm tronpy.tar.gz
    cd ..
  fi
  # make "import coincurve" non-fatal (read-only use never reaches signing code)
  python3 - <<'PY'
import re, pathlib
for rel in ("tronpy/keys/__init__.py", "tronpy/hdwallet/_utils.py"):
    p = pathlib.Path("vendor/tronpy-src") / rel
    s = p.read_text()
    if "  # coincurve optional" in s:
        continue
    s = s.replace(
        "from coincurve import PrivateKey as CoincurvePrivateKey\n",
        "try:  # coincurve optional\n"
        "    from coincurve import PrivateKey as CoincurvePrivateKey\n"
        "except ImportError:\n"
        "    CoincurvePrivateKey = None  # signing unavailable, read-only calls fine\n",
    )
    if "PublicKey" in s and "CoincurvePublicKey = None" not in s:
        s = s.replace(
            "from coincurve import PublicKey as CoincurvePublicKey\n",
            "try:  # coincurve optional\n"
            "    from coincurve import PublicKey as CoincurvePublicKey\n"
            "except ImportError:\n"
            "    CoincurvePublicKey = None\n",
        )
    p.write_text(s)
PY
  ./venv/bin/pip install -q base58 eth-abi httpx pycryptodome requests python-dotenv hatchling telethon
  ./venv/bin/pip install -q --no-deps --no-build-isolation ./vendor/tronpy-src
fi

./venv/bin/python -c "import tronpy, dotenv; from importlib.metadata import version; print('tronpy', version('tronpy'), '| python', __import__('sys').version.split()[0])"
echo "venv ready: source venv/bin/activate"
