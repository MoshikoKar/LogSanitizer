# Advanced Log Sanitizer

## Description
This Python script provides a GUI-based tool for sanitizing log files by removing or replacing sensitive information using regular expression (regex) patterns. It supports loading text and Office files (Word, Excel, PowerPoint), applying customizable sanitization patterns, and saving the sanitized output as text or Word documents. The tool includes a pattern management interface, configuration file support, and logging for debugging.

## Features
- **Input Options**: Load from text files, Office files (DOCX, XLSX, PPTX), or paste from clipboard.
- **Sanitization**: Apply predefined and custom regex patterns to replace sensitive data (e.g., emails, IPs, usernames).
- **Pattern Management**: Add, edit, enable/disable patterns via a treeview interface.
- **Config Support**: Load and save patterns to/from JSON config files.
- **Output Options**: Save sanitized text as `.txt` or `.docx`, or copy to clipboard.
- **Progress Tracking**: Displays progress and status during operations.
- **Logging**: Logs actions and errors to `logs/sanitizer.log` with rotation (5MB, 3 backups).
- **Background Processing**: Uses threads and a queue for non-blocking file operations.
- **Default Patterns**: Includes patterns for emails, IPs, GUIDs, SIDs, usernames, hostnames, etc.

## Requirements
- **Python 3.x**
- **Tkinter** (usually included with Python; install via `pip install tk` if missing)
- **Optional Libraries** (for Office file support):
  - `python-docx` (`pip install python-docx`) for Word documents
  - `pandas` and `openpyxl` (`pip install pandas openpyxl`) for Excel files
  - `python-pptx` (`pip install python-pptx`) for PowerPoint files
- **Standard Libraries**: `re`, `os`, `socket`, `json`, `logging`, `hashlib`, `threading`, `queue`, `time`

## Usage
1. **Run the Script**:
   - Save the script as `log_sanitizer.py`.
   - Install optional libraries for Office support if needed (see Requirements).
   - Execute with Python: `python log_sanitizer.py`.
   - A GUI window titled "Advanced Log Sanitizer" will appear (minimum size: 800x600).

2. **Load Input**:
   - **Text File**: Click "Load from File" to select a `.txt` or `.log` file.
   - **Office File**: Click "Load Word/Office File" to load `.docx`, `.xlsx`, or `.pptx` files (requires respective libraries).
   - **Clipboard**: Click "Paste from Clipboard" or press `Ctrl+V` to paste text.

3. **Manage Patterns**:
   - View patterns in the "Sanitization Patterns" treeview (✓ = enabled, ✗ = disabled).
   - Double-click or use "Enable/Disable" to toggle pattern status.
   - Click "Add" or "Edit" to create/modify patterns with regex, replacement text, and options (case sensitivity, hashing).

4. **Sanitize**:
   - Click "SANITIZE LOG" to process the input text.
   - Progress bar updates during sanitization; output appears in the "Sanitized Output" area.
   - A summary shows time taken and replacements made.

5. **Save Output**:
   - **Text File**: Click "Save to File" to save as `.txt`.
   - **Word File**: Click "Save as Word File" to save as `.docx` (requires `python-docx`).
   - **Clipboard**: Click "Copy to Clipboard" to copy sanitized text.

6. **Config Management**:
   - **Load Config**: Click "Load Config" to import a `.json` file with custom patterns (e.g., `config.json`).
   - **Save Config**: Click "Save Config" to export current patterns to a `.json` file.

## Example Workflow
- Load `log.txt` containing `User: jdoe, Email: jdoe@example.com`.
- Default patterns replace it with `User: <USERNAME>, Email: <EMAIL>`.
- Click "SANITIZE LOG".
- Save as `log_sanitized.txt`.

## Output
- **Log File**: `logs/sanitizer.log` records actions (e.g., "Loaded file: log.txt", "Sanitization completed: 2 replacements").
- **Sanitized Text**: Appears in the output text area and can be saved/copied.
- **Status Bar**: Shows messages like "Loaded: log.txt" or "Sanitized in 0.12s: 2 replacements".

## Notes
- **Office Support**: Requires additional libraries; without them, fallback messages are shown in the output.
- **Config File**: Default config (`config.json`) loads automatically if present in the script directory.
- **Error Handling**: Displays errors in message boxes and logs them; uncaught exceptions are logged and shown.
- **Customization**: Add custom patterns via GUI or config file; see `config.json` README for format.

## Known Limitations
- Excel and PowerPoint support requires specific libraries; unsupported formats fall back to text warnings.
- No real-time preview during pattern editing; sanitize to see changes.
- Large files may slow down processing due to regex operations.

## License
This script is provided as-is for personal or educational use. Feel free to modify it to suit your needs!
