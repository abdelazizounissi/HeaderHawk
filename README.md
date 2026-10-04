# 🦅 HeaderHawk

A command-line tool that scans a website's HTTP response headers, checks them against security best practices, and grades the site from **A to F** with a clean, color-coded report.

<img width="1126" height="322" alt="Screenshot 2026-10-04 174241" src="https://github.com/user-attachments/assets/20bbf21d-6a5e-4f7e-8fde-b672d9ec2fec" />

## ✨ Features

- **Security Header Analysis**: Checks 6 important response headers
- **Smart Validation**: Detects headers that are present but misconfigured (for example `max-age=0` on HSTS)
- **Severity-Based Scoring**: High, medium, and low severity headers are weighted differently
- **A to F Grade**: One score out of 100 and a letter grade at a glance
- **Fix Recommendations**: Shows the exact header line to add for every problem found
- **Color-Coded Output**: Green for ok, yellow for weak, red for missing
- **Guided Experience**: ASCII banner, numbered steps, a loading spinner, and helpful tips on errors
- **Interactive Mode**: Run without arguments and the tool asks for a URL
- **Error Handling**: Clear messages for invalid URLs, timeouts, and connection problems

## 🔍 What It Checks

| Header | Severity | Good value looks like |
|---|---|---|
| `Strict-Transport-Security` | High | `max-age` of at least 1 year (31536000) |
| `Content-Security-Policy` | High | Present, without `unsafe-inline` or `unsafe-eval` |
| `X-Content-Type-Options` | Medium | `nosniff` |
| `X-Frame-Options` | Medium | `DENY` or `SAMEORIGIN` |
| `Referrer-Policy` | Low | Present |
| `Permissions-Policy` | Low | Present |

Each header gets one of three statuses:

- 🟢 **ok**: set and useful
- 🟡 **weak**: set, but the value is unsafe or ineffective
- 🔴 **missing**: not set at all

## 📊 How Grading Works

Each header is worth points based on severity (High = 25, Medium = 15, Low = 10). A header earns full points when `ok`, half when `weak`, and none when `missing`. The score is points earned divided by points possible.

| Score | Grade |
|---|---|
| 90 to 100 | A |
| 80 to 89 | B |
| 70 to 79 | C |
| 60 to 69 | D |
| Below 60 | F |

## 📋 Requirements

- Python 3.8 or newer
- Internet connection
- Libraries: `httpx`, `rich`, `pyfiglet` (installed from `requirements.txt`)

## 🚀 Installation & Usage

### Run from Source

1. Clone this repository:
   ```bash
   git clone https://github.com/abdelazizounissi/HeaderHawk.git
   cd HeaderHawk
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv

   # Windows (PowerShell)
   .venv\Scripts\Activate.ps1

   # Mac / Linux
   source .venv/bin/activate
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the HeaderHawk:
   ```bash
   python HeaderHawk.py
   ```

## 🎯 How to Use

| Command | What it does |
|---|---|
| `python scanner.py https://github.com` | Scan a site |
| `python scanner.py example.com` | Scan without typing `https://` (added automatically) |
| `python scanner.py https://github.com --timeout 5` | Wait at most 5 seconds for the server |
| `python scanner.py` | Interactive mode: the tool asks for a URL |
| `python scanner.py --help` | Show all options and examples |

### Options

| Option | Description | Default |
|---|---|---|
| `url` | Site to scan (optional, you are prompted if omitted) | none |
| `--timeout` | Seconds to wait for the server | `10` |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed |
| `1` | Scan failed (invalid URL, timeout, connection error, or no URL entered) |

## 🖼️ Screenshots

<img width="1919" height="1079" alt="Screenshot 2026-10-04 174545" src="https://github.com/user-attachments/assets/6b175613-9b74-4665-952c-4af48a087d9f" />

## ⚙️ How It Works

1. **Fetch**: Sends a GET request with `httpx`, follows redirects, and reads the final response headers.
2. **Check**: Every header has a rule made of a name, a severity, and a small function that judges its value. Rules are stored as data, so adding a new header takes only a few lines.
3. **Score**: Results are weighted by severity and converted into a score and grade.
4. **Report**: `rich` renders the table, grade panel, and recommendations, and `pyfiglet` draws the banner.

The checking and scoring logic is separate from the network code, so it can be tested with hand-written headers and no internet.

## ⚠️ Limitations

- Checks 6 headers and does not parse the full CSP policy
- A site protected by CSP `frame-ancestors` instead of `X-Frame-Options` is reported as missing the latter
- Reads one response, so results may differ by page, region, or user agent
- Built for learning, not as a replacement for tools like securityheaders.com or Mozilla Observatory

## 🗺️ Roadmap

- [ ] Full CSP parsing with directive-level warnings
- [ ] Treat `frame-ancestors` as a valid alternative to `X-Frame-Options`
- [ ] Cookie flag checks (`Secure`, `HttpOnly`, `SameSite`)
- [ ] Scan multiple URLs from a file
- [ ] JSON output and a `--no-banner` flag for scripting
- [ ] Exit code based on grade for CI use

## 🔒 Responsible Use

Only scan websites you own or have permission to test. HeaderHawk sends a single normal GET request and reads public response headers, but responsible habits matter in security work. This tool is for educational and personal use only.

## 🛠️ Building Executable (Optional)

If you want a standalone Windows executable:

```bash
pip install pyinstaller
pyinstaller --onefile scanner.py
```

The result appears in the `dist/` folder.

## 📝 License

This project is open source and available under the MIT License.

## 👤 Author

Abdelaziz Ounissi

[LinkedIn](https://www.linkedin.com/in/abdelaziz-ounissi/) | [GitHub](https://github.com/abdelazizounissi)

© 2026 Abdelaziz Ounissi

## 🤝 Contributing

Feel free to fork this project and submit pull requests for any improvements!

## 📧 Support

If you encounter any issues or have suggestions, please open an issue on GitHub.
