# PT Automation Orchestrator

מכלול אוטומציה לבדיקות חדירה שמבצע 14 בדיקות אבטחה על דומיינים ומפיק דוחות HTML/JSON מקיפים.

## 📋 תכונות (14 בדיקות)

1. **Headers Check** - בדיקת HTTP headers עם ניתוח CSP, Cookies, ו-Referrer-Policy
2. **DNS/Network Layer Analysis** - רישומי A, AAAA, MX, TXT (SPF, DMARC, DKIM) עם זיהוי misconfigurations
3. **Subdomain Discovery** - גילוי subdomains באמצעות subfinder + אימות subdomains חיים
4. **Nuclei Scan** - סריקת פגיעויות פאסיבית עם תבניות (technologies + misconfiguration)
5. **Screenshot** - צילום מסך של הדף הראשי באמצעות Playwright עם WAF bypass
6. **JavaScript Endpoint Extraction** - חילוץ endpoints מ-JavaScript files (LinkFinder או regex fallback)
7. **Secret Finder** - חיפוש סודות ב-JavaScript files (API keys, tokens, passwords)
8. **Wayback Machine** - חיפוש URLs היסטוריים דרך CDX API (מוגבל ל-5000 URLs)
9. **Sucuri SiteCheck** - בדיקת malware/blacklist/בעיות אבטחה דרך API
10. **Check-Host.net** - בדיקת זמינות host ובדיקות רשת עם screenshot
11. **Security Headers** - בדיקת security headers דרך securityheaders.com עם screenshot
12. **SSL/TLS Certificate** - ניתוח תעודת SSL/TLS באמצעות Python ssl library (Subject, Issuer, SAN, Expiry)
13. **Technology Detection** - זיהוי CMS, frameworks ותשתית (WordPress, Magento, וכו')
14. **Cookies Analysis** - ניתוח מפורט של cookies עם קבלת cookie banners אוטומטית

## 📚 ספריות Python

הכלי משתמש בספריות הבאות (רשומות ב-`requirements.txt`):

### Core Libraries
- **jinja2** (>=3.1.2) - ליצירת HTML reports עם templates
- **playwright** (>=1.40.0) - לסקפורציות ולניווט באתרים (headless browser)
- **undetected-playwright** (>=0.3.0) - עקיפת WAF/Cloudflare challenges
- **requests** (>=2.31.0) - קריאות HTTP/HTTPS
- **beautifulsoup4** (>=4.12.0) - פארסינג HTML (לחילוץ titles, parsing headers)
- **python-dotenv** (>=1.0.0) - ניהול משתני סביבה (.env)

### Network & Security
- **dnspython** (>=2.4.2) - שאילתות DNS (A, AAAA, MX, TXT records)
- **urllib3** - ניהול HTTPS connections (מושתקות אזהרות SSL)

### Parsing & Utilities
- **pyyaml** (>=6.0) - פארסינג YAML (לתמיכה ב-SecretFinder)
- **requests-file** (>=1.5.1) - קריאת קבצים מקומיים
- **jsbeautifier** (>=1.14.0) - יפוי JavaScript code (לתמיכה ב-SecretFinder)
- **lxml** (>=4.9.0) - פארסינג HTML מהיר (לתמיכה ב-BeautifulSoup)

### Built-in Python Modules (כבר כלולים ב-Python)
- **ssl** - חיבור SSL/TLS ו-parsing תעודות
- **socket** - חיבורי רשת
- **json** - עיבוד JSON
- **logging** - מערכת לוגים מפורטת
- **subprocess** - הרצת כלים חיצוניים
- **concurrent.futures** - ביצוע מקבילי של משימות
- **time** - מדידת זמן ביצוע
- **signal** - טיפול ב-process termination
- **datetime** - timestamps
- **re** - regular expressions (ל-JS endpoint extraction)
- **random** - randomization ל-WAF bypass
- **http.cookiejar** - ניהול cookies

## 🛠️ כלים חיצוניים נדרשים

### חובה (Required)

#### subfinder
גילוי subdomains
```bash
# macOS (Homebrew)
brew install subfinder

# או דרך Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

#### nuclei
סריקת פגיעויות עם תבניות
```bash
# התקן דרך Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$(go env GOPATH)/bin

# עדכן תבניות (חשוב!)
nuclei -update -ut

# אם יש בעיות הרשאות:
sudo chown -R $(whoami) ~/nuclei-templates
```

#### playwright
דפדפנים headless (מותקן דרך pip + playwright install)
```bash
# לאחר התקנת requirements.txt:
playwright install chromium
```

### אופציונלי (Optional - יש fallback)

#### LinkFinder
חילוץ endpoints מ-JavaScript files (אם לא קיים, הכלי משתמש ב-regex fallback)
```bash
pip3 install linkfinder

# או מ-git:
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt
python3 setup.py install
```

**הערה:** אם LinkFinder לא מותקן, הכלי משתמש ב-regex patterns מתקדמים לחילוץ endpoints.

## 🚀 התקנה

### 1. התקן כלים חיצוניים

```bash
# macOS (Homebrew)
brew install subfinder

# Go tools (nuclei)
export PATH=$PATH:$(go env GOPATH)/bin
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# עדכן תבניות nuclei
nuclei -update -ut

# תיקון הרשאות אם נדרש
sudo chown -R $(whoami) ~/nuclei-templates
```

### 2. התקן Python dependencies

```bash
# צור virtual environment (מומלץ)
python3 -m venv venv
source venv/bin/activate

# התקן packages
pip install -r requirements.txt

# התקן Playwright browsers
playwright install chromium
```

### 3. אימות התקנה

```bash
# בדוק כלים חיצוניים
which subfinder
subfinder -version
nuclei -version

# בדוק Python packages
python3 -c "import jinja2, playwright, requests, bs4, dns.resolver; print('✅ All packages installed')"
```

## 📖 שימוש

### הרצה בסיסית

```bash
# הפעל virtual environment (אם משתמש)
source venv/bin/activate

# הרץ סריקה על דומיין
python3 pt_orchestrator.py example.com
```

### דוגמאות

```bash
# דומיין רגיל
python3 pt_orchestrator.py example.com

# עם www/http/https - הכלי מנקה אוטומטית
python3 pt_orchestrator.py https://www.example.com
python3 pt_orchestrator.py http://example.com/path
python3 pt_orchestrator.py www.example.com:8080

# הכלי ינקה את הקלט אוטומטית ל: example.com
```

### מה קורה בזמן הסריקה?

הכלי מציג progress bar בזמן אמת:
- אחוז התקדמות
- משימות פעילות
- זמן שעבר וזמן משוער נותר
- אזהרות אם משימות נתקעות

## 📂 מבנה התוצאות

כל התוצאות נשמרות ב-`pt_output/`:

```
pt_output/
├── {domain}.json              # דוח JSON מלא עם כל הנתונים
├── {domain}.html              # דוח HTML מקיף עם תוצאות ויזואליות
├── screenshots/               # צילומי מסך
│   ├── {domain}.png           # צילום מסך ראשי
│   ├── {domain}_checkhost.png
│   ├── {domain}_securityheaders.png
│   └── {domain}_cookies.png
└── logs/                      # לוגים מפורטים
    └── pt_scan_YYYYMMDD_HHMMSS.log
```

### דוח HTML - תכונות

הדוח HTML כולל:
- **Technology Detection** - כרטיסים עם טכנולוגיות שזוהו
- **DNS/Network Analysis** - טבלאות מפורטות של רישומי DNS
- **Subdomains Grid** - תצוגה ויזואלית של subdomains חיים עם titles
- **Security Vulnerabilities** - ממצאי Nuclei עם raw output
- **Screenshots** - תמונות קטנות שפותחות ב-lightbox (קליק להגדלה)
- **Cookies Analysis** - טבלה מפורטת של כל ה-cookies
- **JavaScript Endpoints** - רשימה עם חיפוש real-time
- **Wayback URLs** - רשימה עם חיפוש real-time
- **SecretFinder Results** - סודות שנמצאו
- **כל הבדיקות** - טבלה מקיפה של כל התוצאות

## 🔍 דיבוג עם לוגים

### מיקום הלוגים

הלוגים נשמרים ב: `pt_output/logs/pt_scan_YYYYMMDD_HHMMSS.log`

כל סריקה יוצרת קובץ לוג חדש עם timestamp (format: `pt_scan_20251101_002321.log`).

### סוגי הלוגים

המערכת משתמשת ב-Python `logging` עם רמות הבאות:

- **INFO** - מידע כללי על ביצוע המשימות (start, completion, status)
- **WARNING** - אזהרות (timeouts קרובים, בעיות קלות, retries)
- **ERROR** - שגיאות (פקודות שנכשלו, timeouts, exceptions)
- **DEBUG** - פרטים טכניים (פקודות מלאות, debugging info)

**פורמט לוג:**
```
YYYY-MM-DD HH:MM:SS [LEVEL] [TASK_NAME] Message
```

### איך לדבג שגיאות

#### 1. מצא את קובץ הלוג האחרון

```bash
# רשום את הקבצים לפי תאריך (החדש ביותר ראשון)
ls -lt pt_output/logs/ | head -1

# או פתח ישירות את האחרון
cat pt_output/logs/$(ls -t pt_output/logs/ | head -1)
```

#### 2. חפש שגיאות ספציפיות

```bash
# שגיאות בלבד
grep "ERROR" pt_output/logs/pt_scan_*.log

# שגיאות של משימה ספציפית (לדוגמה: NUCLEI)
grep "\[NUCLEI\].*ERROR" pt_output/logs/pt_scan_*.log

# Timeouts
grep "TIMEOUT" pt_output/logs/pt_scan_*.log

# שגיאות SSL
grep "\[SSL\].*ERROR" pt_output/logs/pt_scan_*.log

# שגיאות WAF bypass
grep "\[WAF\]" pt_output/logs/pt_scan_*.log
```

#### 3. בדוק משימות ספציפיות

```bash
# כל המידע על משימה (לדוגמה: HEADERS)
grep "\[HEADERS\]" pt_output/logs/pt_scan_*.log

# משך זמן ביצוע של כל המשימות
grep "completed in" pt_output/logs/pt_scan_*.log

# פקודות שנכשלו
grep "Command failed" pt_output/logs/pt_scan_*.log

# משימות שהצליחו
grep "✓" pt_output/logs/pt_scan_*.log
```

#### 4. צפייה בזמן אמת (Real-time monitoring)

```bash
# Tail לוג בזמן אמת (עדכון אוטומטי תוך כדי סריקה)
tail -f pt_output/logs/pt_scan_$(ls -t pt_output/logs/ | head -1)

# עם סינון לשגיאות ואזהרות בלבד
tail -f pt_output/logs/pt_scan_*.log | grep --line-buffered "ERROR\|WARNING"

# רק מידע על משימה ספציפית (לדוגמה: NUCLEI)
tail -f pt_output/logs/pt_scan_*.log | grep --line-buffered "\[NUCLEI\]"
```

#### 5. דוגמאות לוגים

**לוג מוצלח:**
```
2025-11-01 00:23:21,229 [INFO] [HEADERS] Starting headers check for example.com
2025-11-01 00:23:21,229 [INFO] [HEADERS] Trying HTTPS connection (max 30 redirects)...
2025-11-01 00:23:22,725 [INFO] [HEADERS] ✓ HTTPS succeeded in 1.5s (Status: 200, 0 redirects)
2025-11-01 00:23:22,726 [INFO] [HEADERS] Completed in 1.5s
```

**לוג עם timeout:**
```
2025-11-01 00:23:21,235 [INFO] [NUCLEI] Starting command: nuclei -u https://example.com...
2025-11-01 00:23:21,236 [INFO] [NUCLEI] Timeout set to: 300s
2025-11-01 00:28:21,502 [ERROR] [NUCLEI] ⚠️ TIMEOUT after 300s (actual time: 300.1s)
2025-11-01 00:28:21,503 [ERROR] [NUCLEI] Command that timed out: nuclei -u https://example.com...
```

**לוג עם שגיאה:**
```
2025-11-01 00:23:21,502 [INFO] [CHECKHOST] Querying check-host.net API for www.example.com...
2025-11-01 00:23:21,949 [ERROR] [CHECKHOST] Command failed with return code 1
2025-11-01 00:23:21,950 [ERROR] [CHECKHOST] STDERR: Connection timeout
```

**לוג מוצלח עם פרטים:**
```
2025-11-01 00:23:21,235 [INFO] [NUCLEI] Starting command: nuclei -u https://example.com...
2025-11-01 00:23:21,236 [INFO] [NUCLEI] Timeout set to: 300s
2025-11-01 00:24:40,473 [INFO] [NUCLEI] Command completed successfully in 79.2s
2025-11-01 00:24:40,475 [INFO] [NUCLEI] Found 17 findings
```

#### 6. שגיאות נפוצות ופתרונות

##### "command not found" - כלי לא נמצא

**תסמינים:**
```
[ERROR] [SUBDOMAINS] Command failed with return code 127
[ERROR] [SUBDOMAINS] STDERR: /bin/sh: subfinder: command not found
```

**פתרון:**
```bash
# בדוק שהכלי מותקן
which subfinder
which nuclei

# בדוק PATH
echo $PATH | grep -o "$(go env GOPATH)/bin"

# אם חסר, הוסף ל-PATH
export PATH=$PATH:$(go env GOPATH)/bin
# הוסף ל-~/.zshrc או ~/.bashrc להמשך
```

##### "TEMPLATE LOADING" errors (Nuclei)

**תסמינים:**
```
[ERROR] [NUCLEI] STDERR: [WRN] templates: warning: error loading template...
```

**פתרון:**
```bash
# עדכן תבניות
nuclei -update -ut

# תיקון הרשאות
sudo chown -R $(whoami) ~/nuclei-templates

# בדוק שהתבניות נמצאות
ls -la ~/nuclei-templates/
```

##### "Failed to get certificate" (SSL)

**תסמינים:**
```
[WARNING] [SSL] Failed to get certificate: [Errno 111] Connection refused
```

**פתרון:**
- בדוק שהדומיין פתוח על פורט 443: `curl -I https://example.com`
- בדוק שאין firewall/blocking
- בדוק ב-logs את השגיאה הספציפית

##### "Timeout" warnings

**תסמינים:**
```
[WARNING] [NUCLEI] Command took 285.0s (close to timeout of 300s)
```

**פתרון:**
- משימות ארוכות יכולות לקחת זמן (nuclei עד 5 דקות זה תקין)
- אם המשימה לא התקדמה בכלל - המערכת תעצור אותה אוטומטית
- בדוק בלוג אם המשימה מתקדמת או נתקעה

##### "Cloudflare challenge" / "Human verification"

**תסמינים:**
```
[WARNING] [SCREENSHOT] Cloudflare challenge detected, waiting...
```

**פתרון:**
- המערכת מנסה לעקוף אוטומטית עם `undetected-playwright`
- אם עדיין נכשל - בדוק בלוג את הודעות `[WAF]`
- לפעמים צריך לחכות כמה שניות

##### "Lightbox not opening" (HTML report)

**תסמינים:**
- תמונות לא נפתחות כשקולקים עליהן

**פתרון:**
- זה תוקן ב-commit האחרון
- אם עדיין יש בעיה, בדוק console בדפדפן (F12) לשגיאות JavaScript
- ודא ש-`openLightbox` מוגדר ב-global scope

#### 7. ניתוח ביצועים

```bash
# סכם משכי זמן של כל המשימות
grep "completed in" pt_output/logs/pt_scan_*.log | awk '{print $NF}' | sort -n

# מצא את המשימה הארוכה ביותר
grep "completed in" pt_output/logs/pt_scan_*.log | sort -t's' -k2 -rn | head -1

# ספור משימות שהצליחו vs נכשלו
echo "Success: $(grep '✓' pt_output/logs/pt_scan_*.log | wc -l)"
echo "Errors: $(grep 'ERROR' pt_output/logs/pt_scan_*.log | wc -l)"
```

### צפייה בדוח HTML

```bash
# macOS
open pt_output/example.com.html

# Linux
xdg-open pt_output/example.com.html

# Windows
start pt_output/example.com.html

# או בדפדפן ספציפי
google-chrome pt_output/example.com.html
```

## ⚙️ הגדרות

### Timeouts

ברירת המחדל ב-`pt_orchestrator.py`:

```python
TIMEOUTS = {
    "headers": 30,           # 30 שניות
    "subdomains": 120,       # 2 דקות
    "nuclei": 300,           # 5 דקות
    "screenshot": 60,        # 1 דקה
    "dns": 30,               # 30 שניות
    "js_endpoints": 120,     # 2 דקות
    "secretfinder": 300,     # 5 דקות
    "cookies": 180,          # 3 דקות
}
```

אפשר לשנות את הערכים ב-`pt_orchestrator.py` לפי הצורך.

### Parallel Execution

המערכת רצה עד **8 משימות במקביל** (ThreadPoolExecutor).

אפשר לשנות ב-`pt_orchestrator.py`:
```python
with ThreadPoolExecutor(max_workers=8) as executor:
```

### Domain Normalization

הכלי מנקה אוטומטית קלט של דומיינים:
- מוסיף `https://` אם חסר
- מסיר `www.` אם קיים (חוץ מבדיקות ספציפיות כמו Check-Host)
- מסיר paths (`/path/to/page`) ו-ports (`:8080`)
- מנרמל את הדומיין לפורמט תקין

### Stuck Process Detection

המערכת מזהה משימות שנתקעות (לא מתקדמות) ומסיימת אותן אוטומטית:
- בודקת אם יש התקדמות כל 10 שניות
- אם אין התקדמות במשך זמן ממושך - מסיימת את התהליך
- מציינת בלוג שהיא סיימה את התהליך

## 🔒 אבטחה והתנהגות

- **Timeouts**: כל הסריקות מכבדות timeouts כדי למנוע תקיעה
- **Rate Limiting**: API calls כוללות עיכובים של 1-2 שניות
- **WAF Bypass**: עקיפת Cloudflare/WAF באמצעות `undetected-playwright` + fingerprinting
- **Audit Trail**: הלוגים כוללים מי הריץ, מתי, ומה (timestamped logs)
- **Raw Outputs**: כל ה-outputs הגולמיים נשמרים כראיות
- **Process Cleanup**: תהליכים שנכשלו מסתיימים בצורה נקייה (process tree killing)

**⚠️ שימוש אתי:** השתמש רק על דומיינים שבבעלותך או שיש לך הרשאה מפורשת לבדוק!

## 🐛 Troubleshooting

### בעיות התקנה

**Python packages לא מתקינים:**
```bash
# עדכן pip
pip install --upgrade pip

# נסה שוב
pip install -r requirements.txt
```

**Playwright browsers לא מתקינים:**
```bash
playwright install chromium --force
```

**Go tools לא נמצאים:**
```bash
# ודא ש-Go מותקן
go version

# הוסף Go bin ל-PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
```

### בעיות ריצה

**"ModuleNotFoundError":**
```bash
# ודא ש-venv פעיל
source venv/bin/activate

# התקן שוב
pip install -r requirements.txt
```

**"Permission denied" ב-logs:**
```bash
# בדוק הרשאות
ls -la pt_output/logs/

# תיקון הרשאות
chmod -R 755 pt_output/
```

**הסריקה נתקעת:**
- בדוק בלוג אם יש אזהרות
- בדוק אם יש תהליכים תקועים: `ps aux | grep nuclei`
- עצור תהליכים תקועים: `pkill -f nuclei`

## 📝 מבנה הפרויקט

```
pt_automation/
├── pt_orchestrator.py      # הקוד הראשי
├── requirements.txt         # Python dependencies
├── templates/
│   └── report.html          # Template ל-HTML report
├── tools/
│   └── secretfinder/       # SecretFinder tool
├── pt_output/              # תוצאות (לא ב-git)
│   ├── {domain}.json
│   ├── {domain}.html
│   ├── screenshots/
│   └── logs/
└── README.md               # הקובץ הזה
```

## 🔄 עדכונים אחרונים

- ✅ תיקון lightbox - תמונות נפתחות עכשיו כראוי
- ✅ SSL certificate parsing משופר
- ✅ JS endpoints extraction משופר עם regex מתקדם
- ✅ Cookies analysis עם קבלת banners אוטומטית
- ✅ WAF bypass משופר עם undetected-playwright
- ✅ Stuck process detection
- ✅ Progress bar פעיל עם זמן משוער

## 📝 רישיון

כלי זה מיועד לבדיקות אבטחה מורשות בלבד. השתמש באחריות ובצורה אתית.

## 🤝 תרומות

פתוח להצעות שיפור, bug fixes, ותכונות נוספות.

---

**Note:** הדוח ה-HTML כולל lightbox לתמונות, חיפוש real-time, תצוגות מפורטות, וכל המידע מאורגן בצורה נוחה לקריאה.
