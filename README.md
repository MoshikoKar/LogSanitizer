# Advanced Log Sanitizer

## Overview

Advanced Log Sanitizer is a powerful, user-friendly GUI application designed to protect sensitive information by automatically sanitizing log files, documents, and text inputs. With robust pattern-matching capabilities and comprehensive file support, it helps organizations and individuals maintain data privacy and compliance.

## Key Features

### 🔒 Comprehensive Data Protection
- Sanitize sensitive information across various file types
- Support for text, Word, Excel, and PowerPoint documents
- Customizable regex-based sanitization patterns
- Optional data hashing for additional security

### 📁 Flexible Input and Output
- Load files directly or paste from clipboard
- Save sanitized content as text or Word documents
- Copy sanitized text to clipboard
- Export and import sanitization configurations

### 🛠️ Advanced Pattern Management
- Add, edit, and toggle sanitization patterns
- Enable/disable individual patterns
- Support for case-sensitive and case-insensitive matching
- Built-in patterns for common sensitive data types

## System Requirements

### Minimum Requirements
- Python 3.7+
- Tkinter (usually pre-installed)

### Optional Libraries (recommended)
- `python-docx`: Word document support
- `pandas` and `openpyxl`: Excel file processing
- `python-pptx`: PowerPoint file support

## Quick Start Guide

1. **Installation**
   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/advanced-log-sanitizer.git
   
   # Install optional dependencies
   pip install python-docx pandas openpyxl python-pptx
   ```

2. **Running the Application**
   ```bash
   python log_sanitizer.py
   ```

## Usage Walkthrough

### Loading Files
- Click "Load from File" for text logs
- Use "Load Word/Office File" for complex documents
- Paste directly from clipboard

### Sanitization Process
1. Load your document
2. Review existing patterns
3. Add or modify patterns if needed
4. Click "SANITIZE LOG"
5. Review and save sanitized output

### Pattern Management
- Double-click patterns to enable/disable
- Use "Add" to create new sanitization rules
- Configure regex, replacement text, and matching options

## Configuration

### Built-in Patterns
- Email addresses
- IP addresses
- Usernames
- Hostnames
- GUID and SID

### Custom Configuration
- Export/import pattern configurations via JSON
- Supports complex regex patterns
- Configurable case sensitivity

## Logging and Monitoring
- Detailed logging in `logs/sanitizer.log`
- Rotation of log files (5MB, 3 backups)
- Progress tracking during sanitization

## Limitations
- Performance may slow with extremely large files
- Office file support requires additional libraries
- No real-time pattern preview

## Security Considerations
- Patterns are applied sequentially
- Optional data hashing for sensitive information
- Configurable replacement strategies

## Contributing
Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## License
Open-source software. See LICENSE file for details.

## Support
For issues, feature requests, or questions, please open a GitHub issue.