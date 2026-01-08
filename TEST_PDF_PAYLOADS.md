# Testing PDF Payloads - Educational Guide

## Overview

This document provides guidance on testing the PDF Payload Injector tool in a controlled, educational environment.

## Setup Test Environment

### 1. Create Isolated Lab Environment

```bash
# Create virtual environment
python3 -m venv pdf_test_env
source pdf_test_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Create Test PDFs

```bash
# Create a simple test PDF
python3 << 'EOF'
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

c = canvas.Canvas("test_document.pdf", pagesize=letter)
c.drawString(100, 750, "Test Document for Security Research")
c.drawString(100, 730, "This is a test PDF file")
c.drawString(100, 710, "for educational purposes only")
c.save()
EOF
```

## Test Payloads

### 1. Simple Alert JavaScript (Safe)

Create `safe_payload.js`:
```javascript
// Safe test payload - just shows alert
app.alert("Security Test Alert");
console.println("This is a security test");
```

Test it:
```bash
python3 pdf_injector.py \
  --input test_document.pdf \
  --output test_safe.pdf \
  --custom-script safe_payload.js
```

### 2. Information Gathering JavaScript (Safe)

Create `info_gather.js`:
```javascript
// Safe test payload - gathers viewer information
var info = {
  appName: app.appVersion,
  viewerVersion: app.viewerVersion,
  viewerType: app.viewerType,
  platform: app.platform,
  language: app.language
};
console.println("PDF Viewer Info: " + JSON.stringify(info));
app.alert("Viewer: " + info.viewerVersion);
```

Test it:
```bash
python3 pdf_injector.py \
  --input test_document.pdf \
  --output test_info.pdf \
  --custom-script info_gather.js
```

### 3. Test with Different Vulnerabilities

```bash
# Test with CVE-2010-0188 (requires actual payload)
echo "Test payload" > test_payload.txt

python3 pdf_injector.py \
  --input test_document.pdf \
  --output test_cve_2010_0188.pdf \
  --payload test_payload.txt \
  --target windows \
  --cve CVE-2010-0188
```

## Analysis Tests

### 1. Analyze Original PDF

```bash
python3 pdf_injector.py --analyze test_document.pdf
```

Expected output:
- PDF version information
- Page count
- No JavaScript
- No embedded files
- No security concerns

### 2. Analyze Modified PDF

```bash
python3 pdf_injector.py --analyze test_safe.pdf
```

Expected output:
- Modified PDF information
- JavaScript present
- Embedded code details

## Vulnerability Listing Tests

### 1. List All Vulnerabilities

```bash
python3 pdf_injector.py --list-vulns
```

Verify:
- All CVEs are listed
- CVSS scores are correct
- Target OS information is accurate

### 2. List Exploits

```bash
python3 pdf_injector.py --list-exploits
```

Verify:
- Exploit-DB IDs are correct
- Platform information is accurate
- Verified status is shown

## Interactive Mode Tests

### 1. Test Interactive Mode

```bash
python3 pdf_injector.py --interactive
```

Test each option:
1. Inject payload
2. List vulnerabilities
3. List exploits
4. Analyze PDF
5. Exit

## Integration Tests

### 1. Complete Workflow Test

```bash
# Step 1: Create test payload
echo "Test shellcode" > test_shell.bin

# Step 2: Inject into PDF
python3 pdf_injector.py \
  --input test_document.pdf \
  --output test_complete.pdf \
  --payload test_shell.bin \
  --target windows

# Step 3: Verify output
python3 pdf_injector.py --analyze test_complete.pdf

# Step 4: Check file was created
ls -lh test_complete.pdf
```

## Validation Tests

### 1. PDF Structure Validation

```python
# test_pdf_structure.py
import sys
sys.path.insert(0, '.')

from modules.pdf_parser import PDFParser

parser = PDFParser()
content = parser.load_pdf("test_safe.pdf")

if content:
    info = parser.get_pdf_info(content)
    print(f"PDF Valid: {info}")
else:
    print("PDF Invalid")
```

### 2. Payload Validation Test

```python
# test_payload_validation.py
import sys
sys.path.insert(0, '.')

from modules.payload_embedder import PayloadEmbedder

embedder = PayloadEmbedder()
test_payload = b"Test payload data"

is_valid, message = embedder.validate_payload(test_payload, "windows")
print(f"Valid: {is_valid}, Message: {message}")
```

## Debug Mode Tests

### 1. Run with Debug Output

```bash
python3 pdf_injector.py \
  --debug \
  --input test_document.pdf \
  --output test_debug.pdf \
  --custom-script safe_payload.js
```

Check log file:
```bash
cat pdf_injector.log
```

## Error Handling Tests

### 1. Test Invalid PDF

```bash
echo "Not a PDF" > fake.pdf

python3 pdf_injector.py \
  --input fake.pdf \
  --output output.pdf \
  --custom-script safe_payload.js
```

Expected: Error message about invalid PDF

### 2. Test Missing Payload

```bash
python3 pdf_injector.py \
  --input test_document.pdf \
  --output output.pdf \
  --payload nonexistent.exe
```

Expected: Error message about missing payload

### 3. Test Invalid CVE

```bash
python3 pdf_injector.py \
  --input test_document.pdf \
  --output output.pdf \
  --payload test_payload.txt \
  --cve CVE-9999-9999
```

Expected: Error message about unknown CVE

## Performance Tests

### 1. Large PDF Test

```bash
# Create larger test PDF
python3 << 'EOF'
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

c = canvas.Canvas("large_test.pdf", pagesize=letter)
for i in range(100):
    c.drawString(100, 750 - (i*10), f"Test line {i}")
    if i % 5 == 0:
        c.showPage()
c.save()
EOF

# Test injection
python3 pdf_injector.py \
  --input large_test.pdf \
  --output large_output.pdf \
  --custom-script safe_payload.js
```

### 2. Multiple Payloads Test

```bash
# Create multiple test payloads
for i in {1..5}; do
  echo "Payload $i" > payload_$i.txt
  
  python3 pdf_injector.py \
    --input test_document.pdf \
    --output test_$i.pdf \
    --payload payload_$i.txt \
    --target windows
done
```

## Cleanup

After testing:

```bash
# Remove test files
rm -f test_*.pdf
rm -f test_*.txt
rm -f test_*.js
rm -f test_*.bin
rm -f large_*.pdf
rm -f payload_*.txt
rm -f pdf_injector.log

# Deactivate virtual environment
deactivate
```

## Test Results Documentation

Create a test report:

```bash
cat > test_report.md << 'EOF'
# PDF Payload Injector Test Report

Date: $(date)
Tester: Your Name
Environment: Kali Linux / Isolated VM

## Tests Performed

### 1. Basic Functionality
- [x] Safe JavaScript injection
- [x] PDF analysis
- [x] Vulnerability listing
- [x] Exploit listing

### 2. Payload Injection
- [x] Windows payload
- [x] Linux payload
- [x] Custom JavaScript

### 3. Error Handling
- [x] Invalid PDF
- [x] Missing payload
- [x] Invalid CVE

### 4. Integration
- [x] Complete workflow
- [x] Validation checks
- [x] Debug mode

## Results

All tests passed successfully. Tool is functioning as expected.

## Notes

- All tests performed in isolated environment
- No actual malicious payloads used
- Focus on functionality and safety
EOF
```

## Safety Precautions

⚠️ **IMPORTANT:**
- Never test with real malicious payloads
- Always use isolated environments
- Scan all test files with antivirus
- Keep test systems offline
- Document all test activities
- Obtain proper authorization

## Next Steps

After successful testing:
1. Review documentation
2. Practice with safe payloads
3. Study CVE and exploit information
4. Learn about PDF security
5. Understand vulnerability mechanics
6. Practice responsible disclosure

## Educational Resources

- OWASP PDF Security Guide
- NIST PDF Security Standards
- Adobe Security Bulletins
- CVE Database
- Exploit-DB Research Papers

---

**Remember: This is for educational purposes only. Always use ethically and legally.**