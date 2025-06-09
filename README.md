# Litepub Browser

A secure graphical browser for the Litepub protocol, built with Python and PyQt6. This browser provides a desktop application interface for browsing Litepub content with advanced security features and EPUB content rendering.

## Features

### Security
- **TLS-encrypted connections** with TOFU (Trust On First Use) certificate validation
- **Certificate fingerprint storage** for persistent security validation
- **Basic authentication handling** over secure connections
- **Input validation and sanitization** to prevent security vulnerabilities
- **File size limits** and safe filename handling

### Content Rendering
- **EPUB content parsing and display** with full HTML/CSS support
- **Image extraction and caching** from EPUB files
- **Embedded and external image support** with data URL fallbacks
- **HTML processing** with proper content wrapping and styling

### Navigation & UI
- **Navigation history** with back/forward buttons
- **Address bar** with URL validation and formatting
- **Link support** within EPUB content for internal navigation
- **Download functionality** to save current EPUB content
- **Debug window** for viewing HTML source
- **Authentication dialogs** when credentials are required

### Architecture
- **Asynchronous networking** using aiohttp for non-blocking requests
- **Multi-threaded design** with proper Qt integration
- **Temporary file management** with automatic cleanup
- **Modular class structure** for maintainability

## Installation

1. Clone or download this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the browser:
```bash
cd browser
python browser.py
```

## Usage

### Basic Navigation
1. **Enter a Litepub URL** in the address bar:
   - `litepub://localhost:8181/` (local server)
   - `litepub://example.com/path/to/page`
   - `litepub://server.com:8080/book/chapter1`

2. **Navigate through content**:
   - Use back/forward buttons in the toolbar
   - Click links within EPUB content
   - Enter new URLs in the address bar

3. **Handle authentication**:
   - When prompted, enter username and password
   - Credentials are sent securely over TLS
   - Failed authentication will prompt for retry

### Security Features
- **First connection**: You'll be prompted to trust new server certificates
- **Certificate changes**: You'll be warned if a server's certificate changes
- **Certificate storage**: Fingerprints are stored in the `certs/` directory
- **Safe downloads**: File size limits and validation prevent malicious content

### File Management
- **Download EPUB**: Use File → Download Current EPUB to save content
- **Temporary files**: Images and content are cached during browsing
- **Automatic cleanup**: Temporary files are removed when closing the browser

## Architecture & Dependencies

The browser is built using modern Python technologies:

### Core Dependencies
- **PyQt6** (≥6.6): Cross-platform GUI framework with native widgets
- **aiohttp** (≥3.9): Asynchronous HTTP client for fast, non-blocking requests
- **cryptography** (≥42): TLS certificate handling and SHA-256 fingerprinting
- **ebooklib** (≥0.18): High-level EPUB parsing and content extraction
- **lxml** (≥5.2): Fast XML/HTML processing for content manipulation

### Key Components
- **LitepubBrowser**: Main window and application controller
- **CertificateManager**: TOFU certificate validation and storage
- **ImageExtractor**: EPUB image extraction and caching
- **HTMLProcessor**: Content processing and HTML generation
- **URLValidator**: Security validation for URLs and inputs
- **AuthDialog**: User authentication interface

## Security Model

This browser implements a robust security model:

1. **Transport Security**: All connections use TLS encryption
2. **Certificate Validation**: TOFU model with fingerprint storage
3. **Input Sanitization**: URL and filename validation
4. **Resource Limits**: File size and download limits
5. **Safe Parsing**: Secure EPUB and HTML processing

## Development

To contribute or modify the browser:

1. **Code Structure**: Main logic is in `browser/browser.py`
2. **Dependencies**: Listed in `requirements.txt` with version constraints
3. **Certificates**: Stored in `certs/` directory (auto-created)
4. **Logging**: Debug information available via Python logging

## License

This project is licensed under the [GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.html).
You may use it in closed-source or commercial projects as long as the terms of the license are followed.