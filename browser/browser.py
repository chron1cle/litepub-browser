import sys
import os
import ssl
import base64
import json
import zipfile
import io
import logging
import threading
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Union
from urllib.parse import urlparse, urljoin
import aiohttp
import asyncio
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QTextBrowser, QMessageBox, QDialog,
    QLabel, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QUrl, pyqtSignal, QObject, QTimer, QEventLoop, QMetaObject
from PyQt6.QtGui import QAction, QIcon
import ebooklib
from ebooklib import epub
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import tempfile
import datetime
import socket
import typing
from PyQt6.QtCore import pyqtSlot

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Security constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp', '.tiff'}
ALLOWED_IMAGE_MIME_TYPES = {
    'image/png', 'image/jpeg', 'image/gif', 'image/svg+xml', 
    'image/webp', 'image/bmp', 'image/tiff'
}
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass

class EPUBParsingError(Exception):
    """Raised when EPUB parsing fails."""
    pass

class AsyncHelper(QObject):
    def __init__(self):
        super().__init__()
        self.loop = None
        self.thread = None
        self._start_loop()

    def _start_loop(self):
        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()

        self.thread = threading.Thread(target=run_loop, daemon=True)
        self.thread.start()

    def create_task(self, coro):
        if not self.loop:
            raise RuntimeError("Event loop not started")
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def run_until_complete(self, coro):
        future = self.create_task(coro)
        return future.result()

class CertificateManager:
    def __init__(self, cert_dir: str = "certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        self.fingerprints: Dict[str, str] = self._load_fingerprints()
        logger.debug(f"Loaded fingerprints: {self.fingerprints}")

    @staticmethod
    def _key(host: str) -> str:
        """Strip port / scheme, force-lower-case."""
        return host.split(":", 1)[0].lower()

    def _load_fingerprints(self) -> Dict[str, str]:
        try:
            fingerprint_file = self.cert_dir / "fingerprints.json"
            if fingerprint_file.exists():
                with open(fingerprint_file, "r") as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading fingerprints: {e}")
            return {}

    def _save_fingerprints(self):
        try:
            fingerprint_file = self.cert_dir / "fingerprints.json"
            with open(fingerprint_file, "w") as f:
                json.dump(self.fingerprints, f, indent=2)
            logger.debug(f"Saved fingerprints to {fingerprint_file}")
        except Exception as e:
            logger.error(f"Error saving fingerprints: {e}")

    def get_fingerprint(self, host: str) -> Optional[str]:
        fingerprint = self.fingerprints.get(self._key(host))
        logger.debug(f"Retrieved fingerprint for {host}: {fingerprint}")
        return fingerprint

    def store_fingerprint(self, host: str, fingerprint: str):
        logger.debug(f"Storing fingerprint for {host}: {fingerprint}")
        self.fingerprints[self._key(host)] = fingerprint
        self._save_fingerprints()
        
        # Also store the certificate in a separate file
        try:
            cert_file = self.cert_dir / f"{self._key(host)}.pem"
            with open(cert_file, "w") as f:
                f.write(f"# Certificate fingerprint: {fingerprint}\n")
                f.write(f"# Host: {self._key(host)}\n")
                f.write(f"# Stored: {datetime.datetime.now().isoformat()}\n")
            logger.debug(f"Stored certificate info in {cert_file}")
        except Exception as e:
            logger.error(f"Error storing certificate info: {e}")

    def verify_certificate(self, host: str, cert_data: bytes) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            stored = self.get_fingerprint(host)
            
            if stored is None:
                logger.debug(f"First connection to {host}, storing fingerprint")
                self.store_fingerprint(host, fingerprint)
                return True
            
            if stored != fingerprint:
                logger.warning(f"Certificate fingerprint mismatch for {host}")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Certificate verification error: {e}")
            return False

class URLValidator:
    """Validates and sanitizes URLs for security."""
    
    @staticmethod
    def is_safe_host(host: str) -> bool:
        """Check if host is safe (no path traversal, etc.)."""
        if not host or len(host) > 253:  # RFC 1035 limit
            return False
        # Basic validation - could be enhanced
        return not any(char in host for char in ['..', '/', '\\', ' '])
    
    @staticmethod
    def sanitize_path(path: str) -> str:
        """Sanitize URL path to prevent path traversal."""
        # Remove any path traversal attempts
        path = path.replace('..', '').replace('//', '/')
        if not path.startswith('/'):
            path = '/' + path
        return path

class ImageExtractor:
    """Handles image extraction from EPUB files."""
    
    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
        self.image_cache: Dict[str, Path] = {}
    
    def _is_safe_filename(self, filename: str) -> bool:
        """Check if filename is safe to use."""
        if not filename or len(filename) > 255:
            return False
        # Remove directory components
        filename = os.path.basename(filename)
        return SAFE_FILENAME_PATTERN.match(filename) is not None
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe filesystem use."""
        filename = os.path.basename(filename)  # Remove any directory components
        # Keep only safe characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        if not filename:
            filename = "image.png"
        return filename[:255]  # Limit length
    
    def extract_from_epub_items(self, epub_book) -> None:
        """Extract images using ebooklib's item parsing."""
        logger.debug("Extracting images using ebooklib...")
        
        for item in epub_book.get_items():
            is_image = self._is_image_item(item)
            
            if is_image:
                try:
                    self._extract_item_image(item)
                except Exception as e:
                    logger.error(f"Error extracting image {item.file_name}: {e}")
    
    def _is_image_item(self, item) -> bool:
        """Check if an item is an image."""
        # Check by type
        if item.get_type() == ebooklib.ITEM_IMAGE:
            logger.debug(f"Found image item by type: {item.file_name}")
            return True
        
        # Check by file extension
        if any(item.file_name.lower().endswith(ext) for ext in ALLOWED_IMAGE_EXTENSIONS):
            logger.debug(f"Found image item by extension: {item.file_name}")
            return True
        
        # Check by media type
        if hasattr(item, 'media_type') and item.media_type in ALLOWED_IMAGE_MIME_TYPES:
            logger.debug(f"Found image item by media type: {item.file_name} ({item.media_type})")
            return True
        
        return False
    
    def _extract_item_image(self, item) -> None:
        """Extract a single image item."""
        if not self._is_safe_filename(item.file_name):
            logger.warning(f"Unsafe filename, skipping: {item.file_name}")
            return
        
        content = item.get_content()
        if len(content) > MAX_FILE_SIZE:
            logger.warning(f"Image too large, skipping: {item.file_name}")
            return
        
        filename = self._sanitize_filename(item.file_name)
        file_path = self.temp_dir / filename
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        self._cache_image(item.file_name, file_path)
        logger.debug(f"Extracted image: {item.file_name} -> {file_path}")
    
    def extract_from_zip(self, epub_data: bytes) -> None:
        """Extract images directly from ZIP when ebooklib fails."""
        if self.image_cache:  # Already have images
            return
        
        logger.debug("No images found by ebooklib, trying direct ZIP extraction...")
        
        try:
            with zipfile.ZipFile(io.BytesIO(epub_data), 'r') as zip_file:
                for name in zip_file.namelist():
                    if self._is_image_file(name):
                        self._extract_zip_image(zip_file, name)
        except Exception as e:
            logger.error(f"Error reading ZIP file for image extraction: {e}")
    
    def _is_image_file(self, filename: str) -> bool:
        """Check if filename represents an image file."""
        return any(filename.lower().endswith(ext) for ext in ALLOWED_IMAGE_EXTENSIONS)
    
    def _extract_zip_image(self, zip_file: zipfile.ZipFile, name: str) -> None:
        """Extract a single image from ZIP file."""
        logger.debug(f"Found image in ZIP: {name}")
        
        if not self._is_safe_filename(name):
            logger.warning(f"Unsafe filename in ZIP, skipping: {name}")
            return
        
        try:
            image_data = zip_file.read(name)
            if len(image_data) > MAX_FILE_SIZE:
                logger.warning(f"Image too large in ZIP, skipping: {name}")
                return
            
            filename = self._sanitize_filename(name)
            file_path = self.temp_dir / filename
            
            with open(file_path, 'wb') as f:
                f.write(image_data)
            
            self._cache_image(name, file_path)
            logger.debug(f"Extracted image from ZIP: {name} -> {file_path}")
        except Exception as e:
            logger.error(f"Error extracting image {name} from ZIP: {e}")
    
    def _cache_image(self, original_name: str, file_path: Path) -> None:
        """Cache image with multiple possible lookup keys."""
        filename = os.path.basename(original_name)
        
        cache_keys = [
            original_name,  # Full original path
            filename,  # Just the filename
            original_name.lstrip('../'),  # Remove relative path prefixes
            f"OEBPS/{filename}",  # Common EPUB structure
            original_name.replace('OEBPS/', ''),  # Remove OEBPS prefix
        ]
        
        # Remove duplicates while preserving order
        unique_keys = []
        for key in cache_keys:
            if key not in unique_keys:
                unique_keys.append(key)
        
        for key in unique_keys:
            self.image_cache[key] = file_path
            logger.debug(f"Cached image with key: {key}")
    
    def get_cached_image(self, src: str) -> Optional[Path]:
        """Get cached image path for given source."""
        possible_paths = [
            src,  # Original path
            f"OEBPS/{src}",  # With OEBPS prefix
            os.path.basename(src),  # Just the filename
            src.lstrip('../'),  # Remove any relative path prefixes
            src.split('/')[-1] if '/' in src else src  # Get just the filename part
        ]
        
        for path in possible_paths:
            if path in self.image_cache:
                cached_path = self.image_cache[path]
                if cached_path.exists():
                    logger.debug(f"Found cached image using path: {path}")
                    return cached_path
        
        return None

class HTMLProcessor:
    """Processes EPUB content into displayable HTML."""
    
    def __init__(self, image_extractor: ImageExtractor):
        self.image_extractor = image_extractor
    
    def process_epub_content(self, root, base_url: str) -> str:
        """Process EPUB XHTML content into displayable HTML."""
        namespaces = {
            'xhtml': 'http://www.w3.org/1999/xhtml',
            'epub': 'http://www.idpf.org/2007/ops'
        }
        
        # Process images
        images_to_process = []
        for img in root.xpath('//xhtml:img', namespaces=namespaces):
            src = img.get('src')
            if src:
                images_to_process.append((img, src))
        
        # Process each image
        for img, src in images_to_process:
            self._process_image(img, src, base_url)
        
        # Extract body content
        body_content = root.xpath('//xhtml:body/*', namespaces=namespaces)
        logger.debug(f"Found {len(body_content)} elements in body")
        
        # Convert to HTML
        body_html_parts = []
        for elem in body_content:
            html_str = etree.tostring(elem, method='html', encoding='unicode')
            body_html_parts.append(html_str)
        
        body_html = ''.join(body_html_parts)
        return self._wrap_in_html(body_html)
    
    def _process_image(self, img_element, src: str, base_url: str) -> None:
        """Process a single image element."""
        logger.debug(f"Processing image src: {src}")
        
        cached_path = self.image_extractor.get_cached_image(src)
        
        if cached_path:
            self._set_image_src_from_file(img_element, cached_path)
        else:
            logger.warning(f"Could not find image: {src}")
            logger.debug(f"Available images in cache: {list(self.image_extractor.image_cache.keys())}")
    
    def _set_image_src_from_file(self, img_element, file_path: Path) -> None:
        """Set image src from a file path, with fallback to data URL."""
        try:
            # Try file:// URL first
            file_url = QUrl.fromLocalFile(str(file_path)).toString()
            img_element.set('src', file_url)
            logger.debug(f"Updated image src to: {file_url}")
        except Exception as e:
            logger.warning(f"Failed to create file URL for {file_path}: {e}")
            # Fallback to data URL
            try:
                self._set_image_data_url(img_element, file_path)
            except Exception as e2:
                logger.error(f"Failed to create data URL for {file_path}: {e2}")
    
    def _set_image_data_url(self, img_element, file_path: Path) -> None:
        """Set image src as data URL."""
        with open(file_path, 'rb') as f:
            image_data = f.read()
        
        # Determine MIME type
        ext = file_path.suffix.lower()
        mime_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.webp': 'image/webp'
        }
        mime_type = mime_types.get(ext, 'image/png')
        
        data_url = f"data:{mime_type};base64,{base64.b64encode(image_data).decode()}"
        img_element.set('src', data_url)
        logger.debug(f"Updated image src to data URL (mime: {mime_type})")
    
    def _wrap_in_html(self, body_html: str) -> str:
        """Wrap content in complete HTML document."""
        return f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 20px;
                    color: #333;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                    margin-top: 1.5em;
                    margin-bottom: 0.5em;
                }}
                p {{
                    margin-bottom: 1em;
                }}
                a {{
                    color: #3498db;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
                code {{
                    background-color: #f8f9fa;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-family: monospace;
                }}
                img {{
                    max-width: 100%;
                    height: auto;
                    display: block;
                    margin: 1em auto;
                }}
            </style>
        </head>
        <body>
            {body_html}
        </body>
        </html>
        """

class AuthDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentication Required")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Username
        username_layout = QHBoxLayout()
        username_layout.addWidget(QLabel("Username:"))
        self.username = QLineEdit()
        username_layout.addWidget(self.username)
        layout.addLayout(username_layout)
        
        # Password
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.password)
        layout.addLayout(password_layout)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)

    def get_credentials(self) -> tuple[str, str]:
        return self.username.text(), self.password.text()

class LitepubBrowser(QMainWindow):
    """Main browser window for Litepub content."""
    
    # Define a signal for content updates
    content_update_signal = pyqtSignal(str)
    
    _dialog_result: bool | None = None
    _auth_credentials: tuple[str, str] | None = None

    # ------------------------------------------------------------------
    @pyqtSlot()                      # <-- no arguments
    def _show_dialog_slot(self):
        # self._dialog_builder has been set by confirm_dialog()
        box = self._dialog_builder()
        self._dialog_result = (
            box.exec() == QMessageBox.StandardButton.Yes
        )

    @pyqtSlot()                      # <-- no arguments
    def _show_auth_dialog_slot(self):
        # self._auth_dialog has been set by show_auth_dialog()
        if self._auth_dialog.exec() == QDialog.DialogCode.Accepted:
            self._auth_credentials = self._auth_dialog.get_credentials()
        else:
            self._auth_credentials = None
        
    def confirm_dialog(self, builder) -> bool:
        """
        Run `builder()` in the GUI thread and return True / False.
        Safe to call from any background thread.
        """
        self._dialog_builder = builder   # stash for the slot
        self._dialog_result  = False     # default

        # Call the slot on the GUI thread; block until it finishes
        QMetaObject.invokeMethod(
            self,
            "_show_dialog_slot",
            Qt.ConnectionType.BlockingQueuedConnection,
        )
        return bool(self._dialog_result)

    def show_auth_dialog(self) -> Optional[tuple[str, str]]:
        """
        Show authentication dialog in the GUI thread and return credentials.
        Safe to call from any background thread.
        """
        self._auth_dialog = AuthDialog(self)  # stash for the slot
        self._auth_credentials = None         # default

        # Call the slot on the GUI thread; block until it finishes
        QMetaObject.invokeMethod(
            self,
            "_show_auth_dialog_slot",
            Qt.ConnectionType.BlockingQueuedConnection,
        )
        return self._auth_credentials

    def _error(self, title: str, text: str):
        def _builder():
            m = QMessageBox()
            m.setIcon(QMessageBox.Icon.Critical)
            m.setWindowTitle(title)
            m.setText(text)
            m.setStandardButtons(QMessageBox.StandardButton.Ok)
            return m
        self.confirm_dialog(_builder)   # discard bool

    def __init__(self):
        super().__init__()
        self.cert_manager = CertificateManager()
        self.url_validator = URLValidator()
        self.history: List[str] = []
        self.history_index = -1
        self.current_url: Optional[str] = None
        self.current_epub_data: Optional[bytes] = None
        self.async_helper = AsyncHelper()
        self.temp_dir: Optional[Path] = None
        self.image_extractor: Optional[ImageExtractor] = None
        self.html_processor: Optional[HTMLProcessor] = None
        self._setup_ui()
        self._setup_actions()
        self.content_update_signal.connect(self.update_content)
        logger.debug("Browser initialized")

    def _setup_ui(self):
        self.setWindowTitle("Litepub Browser")
        self.setMinimumSize(800, 600)

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Navigation bar
        nav_layout = QHBoxLayout()
        
        # Back button
        self.back_btn = QPushButton("←")
        self.back_btn.clicked.connect(self.go_back)
        self.back_btn.setEnabled(False)  # Initially disabled
        nav_layout.addWidget(self.back_btn)
        
        # Forward button
        self.forward_btn = QPushButton("→")
        self.forward_btn.clicked.connect(self.go_forward)
        self.forward_btn.setEnabled(False)  # Initially disabled
        nav_layout.addWidget(self.forward_btn)
        
        # Address bar
        self.address_bar = QLineEdit()
        self.address_bar.returnPressed.connect(self.load_url)
        nav_layout.addWidget(self.address_bar)
        
        # Go button
        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.load_url)
        nav_layout.addWidget(self.go_btn)

        # Download button
        self.download_btn = QPushButton("↓")
        self.download_btn.setToolTip("Download current EPUB")
        self.download_btn.clicked.connect(self.download_current_epub)
        self.download_btn.setEnabled(False)  # Initially disabled
        nav_layout.addWidget(self.download_btn)
        
        layout.addLayout(nav_layout)

        # Content area
        self.content = QTextBrowser()
        self.content.setOpenExternalLinks(False)
        self.content.anchorClicked.connect(self.handle_link)
        self.content.setAcceptRichText(True)  # Enable rich text
        self.content.setReadOnly(True)  # Make it read-only
        self.content.setOpenLinks(False)  # Disable opening links in external browser
        
        # QTextBrowser should handle file:// URLs and data URLs natively
        
        # Set some basic styling
        self.content.setStyleSheet("""
            QTextBrowser {
                background-color: white;
                color: black;
                font-family: Arial, sans-serif;
                font-size: 14px;
                padding: 10px;
            }
        """)
        
        layout.addWidget(self.content)

    def _setup_actions(self):
        # Create menu bar
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        # Home action
        home_action = QAction("Home", self)
        home_action.triggered.connect(self.go_home)
        file_menu.addAction(home_action)

    def _format_url_for_display(self, url: str) -> str:
        """Format URL for display in the address bar, hiding default port."""
        if "://" in url:
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path or "/"
        else:
            # Split on first / to separate host from path
            parts = url.split("/", 1)
            host = parts[0]
            path = "/" + parts[1] if len(parts) > 1 else "/"

        # Remove default port if present
        if host.endswith(":8181"):
            host = host[:-5]

        # Reconstruct URL
        if "://" in url:
            return f"{parsed.scheme}://{host}{path}"
        return f"{host}{path}"

    def _parse_url(self, url: str) -> tuple[str, str]:
        """Parse URL into host and path, adding default port."""
        if "://" in url:
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path or "/"
        else:
            # Split on first / to separate host from path
            parts = url.split("/", 1)
            host = parts[0]
            path = "/" + parts[1] if len(parts) > 1 else "/"

        # Add default port if not present
        if ":" not in host:
            host = f"{host}:8181"

        return host, path

    def load_url(self):
        url = self.address_bar.text()
        
        # Handle litepub:// URLs
        if url.startswith("litepub://"):
            qurl = QUrl(url)
            self._handle_litepub(qurl)
            return
            
        # Handle URLs without scheme
        if not url.startswith("litepub://"):
            url = "litepub://" + url
            
        # Create QUrl and handle it
        qurl = QUrl(url)
        if qurl.isValid():
            self._handle_litepub(qurl)
        else:
            self._error("Invalid URL", f"The URL '{url}' is not valid")

    def navigate_to(self, url: str, update_history: bool = True):
        if url == self.current_url:
            return

        logger.debug(f"Navigating to: {url}")

        if update_history:
            # Update history
            if self.history_index < len(self.history) - 1:
                # If we're not at the end of history, truncate it
                self.history = self.history[:self.history_index + 1]
            self.history.append(url)
            self.history_index = len(self.history) - 1

        # Update navigation buttons
        self.back_btn.setEnabled(self.history_index > 0)
        self.forward_btn.setEnabled(self.history_index < len(self.history) - 1)

        self.current_url = url
        # Display URL without default port
        self.address_bar.setText(self._format_url_for_display(url))
        
        # Create and run the task
        future = self.async_helper.create_task(self.load_page(url))
        future.add_done_callback(self._handle_load_result)

    def _handle_load_result(self, future):
        try:
            future.result()
        except Exception as e:
            logger.error(f"Error loading page: {e}")
            self._error("Error", str(e))

    def update_content(self, html: str):
        """Update the content area with new HTML content."""
        logger.debug("Updating content in UI")
        self.content.setHtml(html)
        logger.debug("Content updated in UI")

    def download_current_epub(self):
        """Save the current EPUB to a file."""
        if not self.current_epub_data:
            self._error("Error", "No EPUB data available to download")
            return

        # Get the filename from the URL
        if "://" in self.current_url:
            parsed = urlparse(self.current_url)
            path = parsed.path
        else:
            path = self.current_url.split("/", 1)[1] if "/" in self.current_url else ""

        # Extract filename from path
        filename = path.split("/")[-1]
        if not filename:
            filename = "page.epub"
        elif not filename.endswith(".epub"):
            filename += ".epub"

        # Open file save dialog
        from PyQt6.QtWidgets import QFileDialog
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save EPUB",
            filename,
            "EPUB Files (*.epub);;All Files (*.*)"
        )

        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(self.current_epub_data)
                logger.debug(f"Successfully saved EPUB to {save_path}")
            except Exception as e:
                logger.error(f"Error saving EPUB: {e}")
                self._error("Error", f"Failed to save EPUB: {str(e)}")

    def _cleanup_temp_dir(self):
        """Clean up the current temporary directory and its contents."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                logger.error(f"Error cleaning up temporary directory: {e}")
        self.temp_dir = None
        self.image_extractor = None
        self.html_processor = None

    async def load_page(self, url: str):
        """Load and display an EPUB page from the given URL."""
        logger.debug(f"Loading page: {url}")
        
        try:
            # Validate URL
            if not self._validate_url(url):
                raise SecurityError(f"Invalid or unsafe URL: {url}")
            
            # Clean up previous resources
            self._cleanup_temp_dir()
            
            # Fetch EPUB data
            epub_data = await self._fetch_epub_with_auth(url)
            if not epub_data:
                return
            
            # Process the EPUB
            await self._process_epub(epub_data, url)
            
        except Exception as e:
            logger.error(f"Error loading page {url}: {e}")
            self._error("Error", f"Failed to load page: {str(e)}")
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL for security."""
        try:
            host, path = self._parse_url(url)
            return self.url_validator.is_safe_host(host)
        except Exception:
            return False
    
    async def _fetch_epub_with_auth(self, url: str) -> Optional[bytes]:
        """Fetch EPUB data, handling authentication if needed."""
        epub_data = await self.fetch_epub(url)
        
        if epub_data is None:
            # Try authentication if we got a 401 response
            if hasattr(self, '_last_response_status') and self._last_response_status == 401:
                logger.debug("Authentication required")
                auth = self.show_auth_dialog()
                if auth:
                    epub_data = await self.fetch_epub(url, auth)
                    if epub_data is None:
                        logger.error("Authentication failed")
                        self._error("Error", "Authentication failed")
                        return None
        
        return epub_data
    
    async def _process_epub(self, epub_data: bytes, url: str):
        """Process EPUB data and update the display."""
        if len(epub_data) > MAX_FILE_SIZE:
            raise SecurityError("EPUB file too large")
        
        # Store the EPUB data for download
        self.current_epub_data = epub_data
        self.download_btn.setEnabled(True)
        
        try:
            # Parse EPUB
            epub_book = await self._parse_epub(epub_data)
            
            # Setup processors
            self.temp_dir = Path(tempfile.mkdtemp())
            self.image_extractor = ImageExtractor(self.temp_dir)
            self.html_processor = HTMLProcessor(self.image_extractor)
            
            # Extract images
            self.image_extractor.extract_from_epub_items(epub_book)
            self.image_extractor.extract_from_zip(epub_data)
            
            # Process content
            html_content = await self._extract_and_process_content(epub_book, url)
            
            if html_content:
                logger.debug(f"Generated HTML content: {len(html_content)} bytes")
                self.content_update_signal.emit(html_content)
            else:
                raise EPUBParsingError("No document content found in EPUB")
                
        except Exception as e:
            logger.error(f"Failed to process EPUB: {e}")
            raise
    
    async def _parse_epub(self, epub_data: bytes):
        """Parse EPUB data and return the book object."""
        logger.debug("Parsing EPUB")
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.epub') as temp_file:
            temp_file.write(epub_data)
            temp_file.flush()
            temp_path = temp_file.name
        
        try:
            epub_book = epub.read_epub(temp_path)
            logger.debug("EPUB parsed successfully")
            
            # Log all items for debugging
            self._log_epub_contents(epub_book, epub_data)
            
            return epub_book
        finally:
            try:
                os.unlink(temp_path)
            except Exception as e:
                logger.error(f"Error cleaning up temporary file: {e}")
    
    def _log_epub_contents(self, epub_book, epub_data: bytes):
        """Log EPUB contents for debugging."""
        logger.debug("EPUB items:")
        for item in epub_book.get_items():
            logger.debug(f"Item: {item.file_name} (type: {item.get_type()}) "
                        f"(media_type: {getattr(item, 'media_type', 'unknown')})")
        
        # Log ZIP contents
        logger.debug("Direct ZIP contents:")
        try:
            with zipfile.ZipFile(io.BytesIO(epub_data), 'r') as zip_file:
                for name in zip_file.namelist():
                    logger.debug(f"ZIP contains: {name}")
        except Exception as e:
            logger.error(f"Error checking ZIP contents: {e}")
    
    async def _extract_and_process_content(self, epub_book, url: str) -> Optional[str]:
        """Extract and process the main content from EPUB."""
        for item in epub_book.get_items():
            if item.get_type() == ebooklib.ITEM_DOCUMENT:
                try:
                    content = item.get_content().decode('utf-8')
                    logger.debug(f"Found document content: {len(content)} bytes")
                    
                    # Parse XHTML content
                    root = etree.fromstring(content.encode('utf-8'))
                    logger.debug("XHTML parsed successfully")
                    
                    # Process and return HTML
                    return self.html_processor.process_epub_content(root, url)
                    
                except Exception as e:
                    logger.error(f"Error processing document {item.file_name}: {e}")
                    continue
        
        return None

    def handle_link(self, url: QUrl):
        scheme = url.scheme()
        if scheme == "litepub":
            self._handle_litepub(url)
        elif scheme in ("http", "https"):
            # For now, just show a warning that only litepub:// links are supported
            QMessageBox.warning(self, "Warning", "Only litepub:// links are supported")
        else:
            QMessageBox.warning(self, "Warning", f"Unsupported URL scheme: {scheme}")

    def _handle_litepub(self, url: QUrl):
        """Handle litepub:// URLs by converting them to https internally."""
        # Get the host and path from the litepub URL
        host = url.host()
        path = url.path()
        
        # If host is empty or "library", use localhost
        if not host or host == "library":
            host = "localhost"
            
        # Add default port if not specified
        if ":" not in host:
            host = f"{host}:8181"
            
        # Construct the internal URL
        internal_url = f"{host}{path}"
        logger.debug(f"Converting litepub URL to internal URL: {internal_url}")
        
        # Navigate to the internal URL
        self.navigate_to(internal_url)

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.navigate_to(self.history[self.history_index], update_history=False)

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.navigate_to(self.history[self.history_index], update_history=False)

    def go_home(self):
        self.navigate_to("litepub://localhost:8181/")

    def _get_ssl_context(self, host: str) -> ssl.SSLContext:
        # Extract just the hostname for certificate storage
        hostname = host.split(":")[0]
        
        context = ssl.create_default_context()
        context.check_hostname = False
        
        stored_fingerprint = self.cert_manager.get_fingerprint(hostname)
        if stored_fingerprint:
            logger.debug(f"Found stored fingerprint for {hostname}: {stored_fingerprint}")
            
            def verify_cert(ssl_sock, cert, errno, depth, return_code):
                if depth == 0:  # Only verify the server certificate
                    try:
                        cert_data = ssl_sock.getpeercert(binary_form=True)
                        if cert_data:
                            cert = x509.load_pem_x509_certificate(cert_data)
                            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                            logger.debug(f"Current certificate fingerprint: {fingerprint}")
                            
                            if fingerprint != stored_fingerprint:
                                logger.warning(f"Certificate fingerprint mismatch for {hostname}")
                                logger.warning(f"Expected: {stored_fingerprint}")
                                logger.warning(f"Got: {fingerprint}")
                                
                                # Show warning dialog on main thread
                                def show_warning():
                                    msg = QMessageBox()
                                    msg.setIcon(QMessageBox.Icon.Warning)
                                    msg.setWindowTitle("Certificate Warning")
                                    msg.setText(f"Certificate for {hostname} has changed!")
                                    msg.setInformativeText("This could indicate a security issue. Do you want to continue?")
                                    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                    msg.setDefaultButton(QMessageBox.StandardButton.No)
                                    
                                    if msg.exec() == QMessageBox.StandardButton.Yes:
                                        # Update stored fingerprint
                                        self.cert_manager.store_fingerprint(hostname, fingerprint)
                                        return True
                                    return False
                                
                                # Run dialog on main thread and wait for result
                                result = asyncio.get_event_loop().run_in_executor(None, show_warning)
                                return result.result()
                            
                            return True
                    except Exception as e:
                        logger.error(f"Certificate verification error: {e}")
                        return False
                return True
            
            context.verify_mode = ssl.CERT_REQUIRED
            context.verify_callback = verify_cert
        else:
            logger.debug(f"No stored fingerprint for {hostname}")
            
            # For first connection, accept any certificate but store its fingerprint
            context.verify_mode = ssl.CERT_NONE
            
            def store_cert(ssl_sock, cert, errno, depth, return_code):
                if depth == 0:  # Only store the server certificate
                    try:
                        logger.debug("Attempting to get certificate data...")
                        cert_data = ssl_sock.getpeercert(binary_form=True)
                        if cert_data:
                            logger.debug(f"Got certificate data: {len(cert_data)} bytes")
                            try:
                                cert = x509.load_pem_x509_certificate(cert_data)
                                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                                logger.debug(f"Extracted fingerprint: {fingerprint}")
                                
                                # Show confirmation dialog on main thread
                                def show_confirm():
                                    msg = QMessageBox()
                                    msg.setIcon(QMessageBox.Icon.Information)
                                    msg.setWindowTitle("New Certificate")
                                    msg.setText(f"New certificate for {hostname}")
                                    msg.setInformativeText(f"Fingerprint: {fingerprint}\n\nDo you want to trust this certificate?")
                                    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                    msg.setDefaultButton(QMessageBox.StandardButton.Yes)
                                    
                                    if msg.exec() == QMessageBox.StandardButton.Yes:
                                        logger.debug("User accepted certificate")
                                        # Store the certificate and fingerprint
                                        self.cert_manager.store_fingerprint(hostname, fingerprint)
                                        
                                        # Also store the full certificate
                                        cert_file = self.cert_dir / f"{hostname}.pem"
                                        logger.debug(f"Writing certificate to {cert_file}")
                                        with open(cert_file, "wb") as f:
                                            f.write(cert_data)
                                        logger.debug(f"Successfully stored certificate in {cert_file}")
                                        return True
                                    logger.debug("User rejected certificate")
                                    return False
                                
                                # Run dialog on main thread and wait for result
                                result = asyncio.get_event_loop().run_in_executor(None, show_confirm)
                                return result.result()
                            except Exception as e:
                                logger.error(f"Error processing certificate: {e}")
                                return False
                        else:
                            logger.error("No certificate data received")
                            return False
                    except Exception as e:
                        logger.error(f"Certificate storage error: {e}")
                        return False
                return True
            
            context.verify_callback = store_cert
            
        return context

    # Helper to run a function on the main Qt thread and wait for the result
    def run_on_main_thread_and_wait(self, func):
        app = QApplication.instance()
        result_container = {}
        def wrapper():
            result_container['result'] = func()
            loop.quit()
        loop = QEventLoop()
        QTimer.singleShot(0, wrapper)
        loop.exec()
        return result_container['result']

    async def _fetch_missing_image(self, base_url: str, image_src: str) -> Optional[Path]:
        """Fetch a missing image from the server and save it to the temp directory."""
        try:
            # Parse the base URL to get host and path
            if "://" in base_url:
                parsed = urlparse(base_url)
                host = parsed.netloc
                base_path = parsed.path or "/"
            else:
                if ":" in base_url:
                    parts = base_url.split("/", 1)
                    host = parts[0]
                    base_path = "/" + parts[1] if len(parts) > 1 else "/"
                else:
                    host = base_url
                    base_path = "/"

            # Construct the image URL
            # Remove the filename from base_path and add the image path
            if base_path.endswith('/'):
                image_url_path = base_path + image_src
            else:
                # Remove the last component (filename) from base_path
                base_dir = '/'.join(base_path.split('/')[:-1])
                if base_dir and not base_dir.endswith('/'):
                    base_dir += '/'
                image_url_path = base_dir + image_src

            # Construct full URL
            full_image_url = f"https://{host}{image_url_path}"
            logger.debug(f"Attempting to fetch missing image from: {full_image_url}")

            # Use the same SSL context and authentication as the main request
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            headers = {"Host": host}
            
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(full_image_url, headers=headers) as response:
                    if response.status == 200:
                        image_data = await response.read()
                        
                        # Save to temp directory
                        if not self.temp_dir:
                            self.temp_dir = Path(tempfile.mkdtemp())
                        
                        # Use just the filename from the src
                        filename = os.path.basename(image_src)
                        if not filename:
                            filename = "image.png"
                        
                        image_path = self.temp_dir / filename
                        with open(image_path, 'wb') as f:
                            f.write(image_data)
                        
                        logger.debug(f"Successfully fetched and saved image: {image_path}")
                        return image_path
                    else:
                        logger.warning(f"Failed to fetch image {full_image_url}: HTTP {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Error fetching missing image {image_src}: {e}")
            return None

    async def fetch_epub(self, url: str, auth: Optional[tuple[str, str]] = None) -> Optional[bytes]:
        """Fetch EPUB data from URL with security validations."""
        try:
            if "://" in url:
                parsed = urlparse(url)
                host = parsed.netloc
                path = parsed.path or "/"
            else:
                if ":" in url:
                    parts = url.split("/", 1)
                    host = parts[0]
                    path = "/" + parts[1] if len(parts) > 1 else "/"
                else:
                    host = url
                    path = "/"

            # Security validations
            if not self.url_validator.is_safe_host(host):
                raise SecurityError(f"Unsafe host: {host}")
            
            path = self.url_validator.sanitize_path(path)

            # Extract host and port
            if ':' in host:
                host_only, port = host.split(':', 1)
                try:
                    port = int(port)
                    if not (1 <= port <= 65535):
                        raise ValueError("Port out of range")
                except ValueError:
                    raise SecurityError(f"Invalid port: {port}")
            else:
                host_only = host
                port = 8181
        except Exception as e:
            logger.error(f"URL parsing/validation error: {e}")
            self._error("Error", f"Invalid URL: {str(e)}")
            return None

        # --- TOFU Certificate Handling (raw socket) ---
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host_only, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host_only) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert)
                    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                    logger.debug(f"[TOFU] Server certificate fingerprint: {fingerprint}")

                    stored_fingerprint = self.cert_manager.get_fingerprint(host)
                    if stored_fingerprint is None:
                        # First connection: prompt user to trust
                        def show_confirm():
                            msg = QMessageBox()
                            msg.setIcon(QMessageBox.Icon.Information)
                            msg.setWindowTitle("New Certificate")
                            msg.setText(f"New certificate for {host}")
                            msg.setInformativeText(f"Fingerprint: {fingerprint}\n\nDo you want to trust this certificate?")
                            msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                            msg.setDefaultButton(QMessageBox.StandardButton.Yes)
                            return msg
                        
                        if self.confirm_dialog(show_confirm):
                            self.cert_manager.store_fingerprint(host, fingerprint)
                            cert_dir = Path("certs")
                            cert_dir.mkdir(exist_ok=True)
                            cert_file = cert_dir / f"{host}.pem"
                            with open(cert_file, "wb") as f:
                                f.write(der_cert)
                        else:
                            raise Exception("Certificate not trusted")
                    elif stored_fingerprint != fingerprint:
                        # Fingerprint changed: warn user
                        def show_warning():
                            msg = QMessageBox()
                            msg.setIcon(QMessageBox.Icon.Warning)
                            msg.setWindowTitle("Certificate Warning")
                            msg.setText(f"Certificate for {host} has changed!")
                            msg.setInformativeText(
                                f"Expected: {stored_fingerprint}\nGot: {fingerprint}\n\nDo you want to trust the new certificate?"
                            )
                            msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                            msg.setDefaultButton(QMessageBox.StandardButton.No)
                            return msg
                        
                        if self.confirm_dialog(show_warning):
                            self.cert_manager.store_fingerprint(host, fingerprint)
                            cert_dir = Path("certs")
                            cert_dir.mkdir(exist_ok=True)
                            cert_file = cert_dir / f"{host}.pem"
                            with open(cert_file, "wb") as f:
                                f.write(der_cert)
                        else:
                            raise Exception("Certificate not trusted")
                    else:
                        logger.debug("[TOFU] Certificate fingerprint matches stored value.")
        except Exception as e:
            logger.error(f"[TOFU] Certificate verification failed: {e}")
            self._error("Certificate Error", str(e))
            return None

        # Proceed with HTTP request (now that cert is trusted)
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Set timeouts for security
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            
            full_url = f"https://{host}{path}"
            logger.debug(f"Fetching EPUB from {full_url}")
            
            headers = {"Host": host, "User-Agent": "Litepub-Browser/1.0"}
            if auth:
                # Validate auth credentials
                if not auth[0] or not auth[1] or len(auth[0]) > 100 or len(auth[1]) > 100:
                    raise SecurityError("Invalid authentication credentials")
                auth_str = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
                headers["Authorization"] = f"Basic {auth_str}"
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(full_url, headers=headers) as response:
                    self._last_response_status = response.status
                    
                    if response.status == 401:
                        logger.debug("Authentication required")
                        return None
                    elif response.status != 200:
                        logger.error(f"HTTP error: {response.status}")
                        raise Exception(f"HTTP {response.status}: {response.reason}")
                    
                    # Check content length
                    content_length = response.headers.get('content-length')
                    if content_length and int(content_length) > MAX_FILE_SIZE:
                        raise SecurityError(f"File too large: {content_length} bytes")
                    
                    # Read with size limit
                    data = bytearray()
                    async for chunk in response.content.iter_chunked(8192):
                        data.extend(chunk)
                        if len(data) > MAX_FILE_SIZE:
                            raise SecurityError("File size exceeded limit during download")
                    
                    logger.debug(f"Successfully fetched EPUB ({len(data)} bytes)")
                    return bytes(data)
                    
        except Exception as e:
            logger.error(f"Error fetching EPUB: {e}")
            self._error("Error", str(e))
            return None

    def show_debug_window(self, html_content: str):
        """Show a debug window with the HTML source."""
        debug_window = QDialog(self)
        debug_window.setWindowTitle("HTML Source")
        debug_window.setMinimumSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Add text browser
        text_browser = QTextBrowser()
        text_browser.setPlainText(html_content)
        layout.addWidget(text_browser)
        
        # Add close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(debug_window.close)
        layout.addWidget(close_btn)
        
        debug_window.setLayout(layout)
        debug_window.exec()

    def closeEvent(self, event):
        """Clean up temporary files when the window is closed."""
        self._cleanup_temp_dir()
        super().closeEvent(event)

def main():
    app = QApplication(sys.argv)
    browser = LitepubBrowser()
    browser.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 