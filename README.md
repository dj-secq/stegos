# Stego Triage

A local steganography workbench. Drop one file, read the leads, and step through bit planes on this machine.

The service is one container. It has no accounts, no database, and no outbound network. Uploads stay in a job directory and are deleted with the job, or after three hours.

## Run

Docker is required.

```bash
docker compose build
./start.sh
```

Open http://127.0.0.1:8786/. The published port is loopback only. `./stop.sh` stops the container.

`./test.sh` creates a virtualenv under `backend/venv` and runs pytest. It does not build the image.

Browser checks need Node.js. From this directory, run `npm install` and then `npx playwright test`. That walks the bench at 1280 and 390. If Chromium is not installed yet, run `npx playwright install chromium` first.

To move an image to a machine that is offline:

```bash
./export-image.sh
# on the other machine
./import-image.sh
./start.sh
```

## What you can drop in

One file, up to 25 MiB.

- Images: preview, per-channel bit planes (bit 0 is the least significant bit), eight color remaps, PNG checks, barcodes.
- Audio: a waveform, and a spectrogram per channel for the first two channels. Pictures stop at 30 seconds.
- PDF: `pdfinfo` as text. The page does not render the PDF.
- GIF: a frame list with delays, capped at 32 frames. Bit planes use the composited preview.
- Text: trailing whitespace, zero-width characters (`U+200B` as 0 and `U+200C` as 1, unless the swapped map is the one that decodes), and unusual spaces such as `U+2003` mixed with ordinary spaces.
- Carving: binwalk, and foremost on a Deep pass. Extracted files are downloads. They are not executed.

Quick runs the checks and carves when a signature is worth extracting. Deep also runs foremost and `zsteg -a`.

Leave the password empty to try a blank password. Steghide uses that blank. The password is removed when the job finishes and is not returned in the results. There is no wordlist.

A flag, a passphrase, or a hash is a lead. A 32-hex value is labeled for a hash identifier. This page does not look it up.

## Tools in the image

Installed at build time: `file`, ExifTool, `strings`, ImageMagick, pngcheck, binwalk, foremost, zsteg, steghide, outguess, poppler (`pdfinfo`), sox, and zbarimg.

jsteg, jpseek, and OpenStego are not installed. Those checks report `unavailable`. pdfid reports `unavailable` unless that program is on the image. An unavailable check is not a failed file.

## Limits

- One job at a time.
- A restart fails a job that was still running.
- Images above 40 megapixels are refused by the picture checks.
- The container root is read-only, capabilities are dropped, and the process is not root.
