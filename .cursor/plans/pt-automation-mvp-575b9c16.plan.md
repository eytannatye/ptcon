<!-- 575b9c16-12e9-4e50-b890-bdb4cb6ad101 54e14313-8fea-49b3-80fb-9529f47567a3 -->
# Adding DNS, CSP/Cookie Analysis, and JavaScript Endpoint Extraction

## Goals

1. **DNS/Network Layer Checks** - Use dnspython to check A, AAAA, MX, TXT records (including SPF, DKIM, DMARC)
2. **CSP & Cookie Analysis** - Analyze Content-Security-Policy, Set-Cookie, and Referrer-Policy from headers
3. **JavaScript Endpoint Extraction** - Use LinkFinder to extract API endpoints from JavaScript files
4. **Excludes** favicon/logo display (cancelled)

## File Changes

### 1. requirements.txt

- Add `dnspython>=2.4.2` for DNS queries
- Add `pyyaml>=6.0` (may be required for LinkFinder)

### 2. pt_orchestrator.py

#### a. Add task_dns (new function)

- Location: After `task_headers`, before `task_subdomains`
- Use `dns.resolver` from dnspython
- Checks:
  - **A records**: `resolver.resolve(domain, 'A')`
  - **AAAA records**: `resolver.resolve(domain, 'AAAA')`
  - **MX records**: `resolver.resolve(domain, 'MX')`
  - **TXT records**: `resolver.resolve(domain, 'TXT')`
- TXT analysis:
  - **SPF**: Search for `v=spf1`
  - **DMARC**: Search for `v=DMARC1`
  - **DKIM**: Search for `v=DKIM1`
- Misconfiguration detection:
  - Missing DNS records
  - SPF records without `-all` or `~all`
  - Missing DMARC records
- Result: `{"dns": result}` with fields: `a_records`, `aaaa_records`, `mx_records`, `txt_records`, `spf`, `dmarc`, `dkim`, `misconfigurations`
- Timeout: 30 seconds

#### b. Enhance task_headers (add CSP & Cookie Analysis)

- Location: Inside `task_headers`, after receiving headers
- Analysis:
  - **Content-Security-Policy**: Extract directives (default-src, script-src, style-src, etc.)
    - Identify `unsafe-inline`, `unsafe-eval` as weaknesses
    - Identify missing directives
  - **Set-Cookie**: Extract cookies
    - Identify flags: `Secure`, `HttpOnly`, `SameSite`
    - Identify cookies without Secure/HttpOnly as weaknesses
  - **Referrer-Policy**: Check value (no-referrer, no-referrer-when-downgrade, etc.)
- Result: Add `csp_analysis`, `cookie_analysis`, `referrer_policy` to `task_headers` result
- No separate task needed - integrated into existing task_headers

#### c. Add task_js_endpoints (new function)

- Location: After `task_screenshot`, before `task_wayback`
- Use LinkFinder
- Steps:

  1. Check if LinkFinder is installed: `which linkfinder` or `linkfinder --version`
  2. Get JavaScript URLs from `task_screenshot` or fetch from site
  3. Run LinkFinder on each JS file:
     ```bash
     linkfinder -i <js_url> -o cli
     ```

  1. Parse output to extract endpoints (URLs, API paths)
  2. Group by base domain

- Fallback: If LinkFinder not installed, use basic regex extractor:
  - `https?://[^"'\s]+` (URLs)
  - `/api/[^"'\s]+` (API paths)
  - `/[a-zA-Z0-9_/]+\.json` (JSON endpoints)
- Result: `{"js_endpoints": result}` with fields: `endpoints` (list), `endpoint_count`, `linkfinder_used` (boolean)
- Timeout: 120 seconds (can take long if many JS files)

#### d. Update TIMEOUTS

- Add `"dns": 30`
- Add `"js_endpoints": 120`

#### e. Update TASKS list

- Add `task_dns` after `task_headers`
- Add `task_js_endpoints` after `task_screenshot`

#### f. Update task_names mapping

- Add `task_dns: "DNS Records"`
- Add `task_js_endpoints: "JavaScript Endpoints"`

### 3. templates/report.html

#### a. Add DNS Results Section

- Location: After "Technologies Detected", before "Subdomains Discovered"
- Title: "DNS / Network Layer Analysis"
- Display:
  - **A Records**: list of IPs
  - **AAAA Records**: list of IPv6 addresses
  - **MX Records**: list with priority
  - **TXT Records**: collapsed section
  - **Email Security**:
    - SPF record (if exists)
    - DMARC record (if exists)
    - DKIM record (if exists)
  - **Misconfigurations**: warnings (if any)
- Styling: Similar to Technologies section

#### b. Add CSP & Cookie Analysis Section

- Location: Inside "Headers" check results (inside detailed results loop)
- Title: "Security Headers Analysis"
- CSP Analysis:
  - Table with directives and values
  - Warnings for `unsafe-inline`, `unsafe-eval`
  - Missing directives list
- Cookie Analysis:
  - Table with cookie names and flags
  - Warnings for cookies without Secure/HttpOnly
- Referrer-Policy: Display value
- Styling: cards/tables similar to Nuclei findings

#### c. Add JavaScript Endpoints Section

- Location: In "Additional Findings" section, after Wayback URLs
- Title: "JavaScript Endpoints Discovered"
- Display:
  - List/Grid of endpoints
  - Grouping by domain
  - Indication if LinkFinder was used or regex fallback
- Search functionality: Similar to Wayback search
- Styling: Similar to Wayback URLs

### 4. README.md

- Update Features list:
  - Add "DNS/Network Layer Analysis"
  - Add "CSP & Cookie Analysis"
  - Add "JavaScript Endpoint Extraction"
- Update Prerequisites:
  - Add LinkFinder installation instructions
- Update Installation:
  - LinkFinder: `pip3 install linkfinder` or `git clone` + installation
- Update Tool Verification:
  - Check `linkfinder --version`

## Implementation Details

### DNS Task (`task_dns`)

```python
import dns.resolver
# A, AAAA, MX, TXT queries
# Parse TXT for SPF/DMARC/DKIM
# Flag misconfigurations
```

### CSP Analysis (inside `task_headers`)

```python
# Parse CSP header
csp = response.headers.get('Content-Security-Policy', '')
# Extract directives
# Check for unsafe-inline, unsafe-eval
# Check for missing important directives
```

### Cookie Analysis (inside `task_headers`)

```python
# Parse Set-Cookie headers
cookies = response.headers.get_list('Set-Cookie')
# Extract flags: Secure, HttpOnly, SameSite
# Check for missing security flags
```

### JS Endpoints (`task_js_endpoints`)

```python
# Check LinkFinder availability
# Fetch JS files from domain
# Run linkfinder -i <url> -o cli
# Parse output
# Fallback to regex if LinkFinder unavailable
```

## Testing Considerations

- Test domain with SPF/DMARC/DKIM records
- Test domain with CSP headers
- Test domain with cookies (Secure/HttpOnly)
- Test domain with JS files (for LinkFinder)
- Fallback test: LinkFinder not installed (regex only)

## Notes

- LinkFinder requires installation - handle graceful fallback
- DNS queries can fail - handle errors
- CSP/Cookie analysis integrated into existing task_headers (not separate task)
- Does not include favicon/logo extraction or display

### To-dos

- [ ] הוספת dnspython ל-requirements.txt
- [ ] יצירת task_dns עם בדיקות A, AAAA, MX, TXT (SPF, DMARC, DKIM)
- [ ] הוספת CSP analysis ל-task_headers (parse directives, identify weaknesses)
- [ ] הוספת Cookie analysis ל-task_headers (parse Set-Cookie, check Secure/HttpOnly)
- [ ] יצירת task_js_endpoints עם LinkFinder + regex fallback
- [ ] הוספת task_dns ו-task_js_endpoints ל-TASKS list ו-task_names
- [ ] הוספת DNS Results section ב-report.html (A, AAAA, MX, TXT, SPF/DMARC/DKIM)
- [ ] הוספת CSP & Cookie Analysis section ב-report.html (בתוך Headers results)
- [ ] הוספת JavaScript Endpoints section ב-report.html עם search
- [ ] עדכון README.md עם LinkFinder installation instructions ופיצרים חדשים