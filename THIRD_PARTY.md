# Third-party software

The application code in this repository is MIT. The container installs these programs at build time. Their licenses stay with their projects.

- Python 3.12 (PSF License)
- Flask 3.0.3 and Werkzeug (BSD)
- Gunicorn (MIT)
- Pillow (HPND)
- NumPy (BSD)
- `file` and binutils `strings` (GPL)
- ExifTool (Perl / Artistic or GPL)
- ImageMagick (ImageMagick License)
- pngcheck (MIT-style)
- binwalk (MIT)
- foremost (public domain)
- zsteg (MIT), via RubyGems
- steghide (GPL)
- outguess (BSD-like)
- poppler-utils, for `pdfinfo` (GPL)
- sox (GPL)
- zbar-tools (LGPL)

jsteg, jpseek, and OpenStego are not fetched or installed. Noto Sans and JetBrains Mono ship in `frontend/assets/fonts/` with their license texts beside the files.

The repository does not vendor those program sources. The Dockerfile installs the Debian packages, and the zsteg gem, while the image is built.
