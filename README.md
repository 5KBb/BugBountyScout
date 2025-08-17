# BugBountyScout

![Descrizione](assets/screenshot.png)


**Made in Italy 🇮🇹** – Strumento CLI per bug bounty che automatizza controlli su **HTTP headers**, **TLS**, **XSS** e **SQLi** con report JSON (opz. cifrati).

## Features
- Header Analysis (CSP, X-CTO, XFO, HSTS, Referrer-Policy, Permissions-Policy)
- SSL/TLS (handshake e scadenza certificato)
- XSS riflessa (payload base)
- SQLi (error-based signatures)
- Report JSON (+ opzionale cifratura **Fernet**)
- CLI stabile `bugbountyscout`

## Installation
```bash
git clone https://github.com/5KBb/BugBountyScout.git
cd BugBountyScout
python -m venv .venv && . .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Usage (CLI)
```bash
# Scansione base
bugbountyscout example.com

# Output dir e threads
bugbountyscout https://example.com -o out/ -t 10 -v

# Report cifrato (Fernet)
bugbountyscout example.com --encrypt-report --key "<FERNET_KEY>"
```

**Exit codes**  
`0` = ok · `1` = errore fatale

### USO con Python
```bash
python bugbountyscout.py example.com -v
```

### Command Line Options
```
usage: bugbountyscout TARGET [-o DIR] [-t N] [-v] [--encrypt-report --key K]
```

### Examples
```bash
bugbountyscout example.com -v
bugbountyscout example.com -o /tmp/reports
bugbountyscout https://example.com?page=1
```

## Understanding Results
Il report `report_YYYYmmdd_HHMMSS.json` contiene:
- `meta`: target, timestamp, versione
- `summary`: conteggio per severità
- `findings[]`: `title`, `severity`, `description`, `recommendation`, `evidence`, `component`

## Ethical Use Statement
BugBountyScout is designed for legitimate security testing with proper authorization. Always ensure you have permission to test the target system. Unauthorized testing may violate laws and terms of service.

## Limitations
- Possibili falsi positivi → verificare manualmente
- Test basilari: non rimpiazza un assessment completo
- Alcuni test possono influenzare l’applicazione target

## Contributing
PR welcome! Prima di inviare:
```bash
pip install -r requirements-dev.txt
pre-commit install
pytest -q
```

## License
Questo repository è rilasciato sotto **GPL-2.0** (vedi `LICENSE`).

## Disclaimer
The developers of BugBountyScout are not responsible for any misuse of this tool or for any damage that may result from using this tool. Use at your own risk and responsibility.

## Changelog (estratto)
- **2.1.0**: hardening rete (timeout/retry), normalizzazione URL, CLI stabile, pin dipendenze, pre-commit, CI, test.

## Conventional commits (esempi)
- `feat(scanner): add TLS expiry warning`
- `fix(cli): normalize scheme when missing`
- `docs(readme): align license to GPL-2.0`
