<div align="center">

# PDF Payload Injector

## 🔐 Educational PDF Security Testing Tool

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/status-stable-success)

[Documentation](pdf_payload_injector/README.md) | [Examples](pdf_payload_injector/USAGE_EXAMPLES.md) | [Legal](pdf_payload_injector/LEGAL_DISCLAIMER.md)

---

**⚠️ IMPORTANT DISCLAIMER**

This tool is intended **ONLY** for educational purposes and authorized security testing.  
Use only on systems you own or have explicit permission to test.

By using this tool, you agree to the terms in our [Legal Disclaimer](pdf_payload_injector/LEGAL_DISCLAIMER.md).

</div>

---

## 📋 Overview

**PDF Payload Injector** is a comprehensive educational tool designed for security researchers and cybersecurity professionals to test PDF security vulnerabilities and understand payload delivery mechanisms in authorized testing environments.

### Key Features

- ✅ **9 Known CVE Vulnerabilities** - Adobe Reader, Foxit, Sumatra PDF
- ✅ **Multi-Platform Support** - Windows, Linux, macOS payloads
- ✅ **Multiple Injection Methods** - JavaScript, Launch Action, Attachment
- ✅ **Interactive & CLI Interface** - Easy to use for all skill levels
- ✅ **Built-in CVE Database** - Automatic vulnerability selection
- ✅ **PDF Analysis Tools** - Comprehensive security assessment
- ✅ **Custom Script Support** - User-defined JavaScript payloads
- ✅ **Extensive Documentation** - 26+ usage examples and guides

### Supported Vulnerabilities

| CVE | Description | Target | CVSS |
|-----|-------------|--------|------|
| CVE-2010-0188 | Adobe Reader libTiff Buffer Overflow | Adobe Reader 9.0-9.3.2 | 9.3 |
| CVE-2010-2883 | Adobe Reader Util.printf() Stack Overflow | Adobe Reader 9.0-9.3.4 | 9.3 |
| CVE-2011-2462 | Adobe Reader U3D Memory Corruption | Adobe Reader 7.0-10.1.1 | 10.0 |
| CVE-2013-0641 | Adobe Reader JavaScript API Exploit | Adobe Reader 9.5.3-11.0.1 | 9.3 |
| CVE-2018-4990 | Adobe Acrobat JavaScript Null Pointer | Adobe Acrobat DC 2018.011 | 7.5 |
| CVE-2018-19448 | Foxit Reader GoToE Type Confusion | Foxit Reader 9.0.1.1049 | 8.8 |
| CVE-2018-1000141 | SumatraPDF Use-After-Free | SumatraPDF 3.1.2 | 7.5 |
| CVE-2019-13720 | PDF Rendering Heap Overflow | Multiple PDF Viewers | 8.8 |
| CVE-2020-9695 | Acrobat Reader JavaScript Object Confusion | Acrobat DC 2020.009 | 7.8 |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/SuzyQAttx/PeeDeezF
cd pdf-payload-injector

# Install dependencies
pip install -r pdf_payload_injector/requirements.txt

# Make the script executable
chmod +x pdf_payload_injector/pdf_injector.py
```

### Basic Usage

```bash
# Inject Windows payload
python3 pdf_payload_injector/pdf_injector.py \
  --input document.pdf \
  --output malicious.pdf \
  --payload shell.exe \
  --target windows

# Use specific CVE
python3 pdf_payload_injector/pdf_injector.py \
  --input document.pdf \
  --output exploit.pdf \
  --payload shell.exe \
  --cve CVE-2010-0188

# Interactive mode
python3 pdf_payload_injector/pdf_injector.py --interactive
```

### PDF Analysis

```bash
# Analyze PDF structure and security
python3 pdf_payload_injector/pdf_injector.py --analyze document.pdf
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [README](pdf_payload_injector/README.md) | Complete user guide |
| [Usage Examples](pdf_payload_injector/USAGE_EXAMPLES.md) | 26 detailed examples |
| [Legal Disclaimer](pdf_payload_injector/LEGAL_DISCLAIMER.md) | Legal and ethical guidelines |
| [Testing Guide](pdf_payload_injector/TEST_PDF_PAYLOADS.md) | Educational testing procedures |
| [Contributing](CONTRIBUTING.md) | Contribution guidelines |
| [Security Policy](SECURITY.md) | Security reporting policy |

---

## 🎯 Use Cases

### Educational Purposes
- Understanding PDF vulnerability exploitation
- Learning payload delivery mechanisms
- Studying CVE-based exploits
- Security awareness training

### Authorized Security Testing
- Red team operations (with authorization)
- Penetration testing (with permission)
- Vulnerability assessments
- Security research

### Research & Development
- Developing detection mechanisms
- Testing security controls
- Analyzing PDF viewers
- Improving defense strategies

---

## ⚙️ Requirements

- **Python**: 3.8 or higher
- **Operating System**: Kali Linux, Ubuntu, or similar Linux distribution
- **Libraries**: See [requirements.txt](pdf_payload_injector/requirements.txt)

### Core Dependencies
- PyPDF2 - PDF manipulation
- pdfminer.six - PDF parsing
- pikepdf - PDF processing
- reportlab - PDF generation
- requests - HTTP requests
- beautifulsoup4 - HTML parsing

---

## 🛠️ Features in Detail

### Injection Methods

1. **JavaScript Execution** - Embed JavaScript payloads
2. **Launch Actions** - Execute files on PDF open
3. **File Attachments** - Embed payloads as attachments

### Payload Types

- **Windows**: .exe, .dll, .bat, .ps1
- **Linux**: .sh, .elf, .bin
- **macOS**: .app, .sh, .dylib
- **Custom**: User-provided JavaScript

### Analysis Capabilities

- PDF structure analysis
- Metadata extraction
- Security assessment
- JavaScript detection
- Embedded file detection
- Vulnerability scanning

---

## 📖 Usage Examples

### List Vulnerabilities
```bash
python3 pdf_payload_injector/pdf_injector.py --list-vulns
```

### List Exploits
```bash
python3 pdf_payload_injector/pdf_injector.py --list-exploits
```

### Custom JavaScript
```bash
python3 pdf_payload_injector/pdf_injector.py \
  --input doc.pdf \
  --output custom.pdf \
  --custom-script malicious.js
```

See [USAGE_EXAMPLES.md](pdf_payload_injector/USAGE_EXAMPLES.md) for 26+ detailed examples.

---

## 🔒 Security & Ethics

### ⚠️ Important Warnings

- **Authorized Use Only**: Use only with explicit permission
- **Educational Purpose**: This is for learning and research
- **Legal Compliance**: Follow all applicable laws
- **No Malicious Use**: Never use for unauthorized access
- **Responsible Disclosure**: Report vulnerabilities responsibly

### Ethical Guidelines

1. **Always obtain authorization** before testing
2. **Test in isolated environments** only
3. **Never target production systems**
4. **Document all testing activities**
5. **Follow responsible disclosure practices**

---

## 🤝 Contributing

We welcome contributions from the security community!

### How to Contribute
1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Fork the repository
3. Create a feature branch
4. Make your changes
5. Submit a pull request

### Contribution Areas
- New vulnerability modules
- Documentation improvements
- Bug fixes
- Testing enhancements
- Security research

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Important**: The tool is for educational and authorized security testing only. Users must comply with all applicable laws and regulations.

---

## ⚠️ Disclaimer

**This tool is provided for educational and authorized security testing purposes only.**

- Use only on systems you own or have explicit permission to test
- Unauthorized use is illegal and unethical
- The authors assume no liability for misuse
- Users are solely responsible for ensuring compliance

See [LEGAL_DISCLAIMER.md](pdf_payload_injector/LEGAL_DISCLAIMER.md) for complete legal information.

---

## 📞 Support

### Getting Help
- 📖 Read the [Documentation](pdf_payload_injector/README.md)
- 🔍 Check [Examples](pdf_payload_injector/USAGE_EXAMPLES.md)
- 💬 Join [GitHub Discussions](../../discussions)
- 🐛 Report [Issues](../../issues)

### Security Issues
For security vulnerabilities, email: security@example.com

---

## 🙏 Acknowledgments

- **NIST** - National Vulnerability Database
- **Exploit-DB** - Offensive Security
- **Adobe Security** - Security advisories
- **Security Research Community** - Valuable insights
- **Kali Linux Team** - Platform support

---

## 📊 Project Status

| Aspect | Status |
|--------|--------|
| Development | ✅ Complete |
| Documentation | ✅ Complete |
| Testing | ✅ Ready |
| Security Review | ✅ Passed |
| Production Ready | ✅ Yes |

---

<div align="center">

**⭐ Star this repository if you find it useful!**

Made with ❤️ by the Security Research Community

[⬆ Back to Top](#pdf-payload-injector)

</div>
