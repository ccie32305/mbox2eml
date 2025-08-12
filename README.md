# mbox-to-eml-export

A Python tool to **convert large Gmail MBOX archives** (via Google Takeout) into individual `.eml` files.  
Designed with **memory efficiency** in mind – can handle very large files (15GB+) without exhausting system resources.  

Perfect for:
- **Archiving and backup** of your Gmail mailbox
- **Feeding `.eml` files into Paperless-ngx** or other document management systems

---

## Features

- **Handles huge MBOX files**  
  Processes files line-by-line without loading the entire archive into RAM.
  
- **Duplicate detection and skipping**  
  Uses a persistent 8-byte hash to avoid exporting the same email more than once – even across multiple runs.

- **Safe, unique filenames**  
  Each exported file name contains:
  - A sequential counter
  - An 8-byte content hash
  - A cleaned subject line (sanitized for filesystem safety)

- **Crash-safe and resumable**  
  Written hashes are stored in a text file, allowing safe restarts without duplicating work.

- **UTF-8 subject decoding**  
  Automatically decodes MIME-encoded email subjects for human-readable filenames.

- **Compatible with Gmail Takeout format**  
  Works directly on `.mbox` files downloaded from Google Takeout.

- **Ideal for Paperless-ngx ingestion**  
  Outputs plain `.eml` files that Paperless-ngx can consume for indexing and archiving.

---

## Example Filename

2025-07-44-email@from.de-Invoice_August_2024-2f1f4770abe5c068.eml
- `2025-07-44` → Date
- 'email@from.de' → Email sender
  `Invoice_August_2024` → Decoded and cleaned subject line 
- `09e243c1301f4cb9` → 8-byte hash from email content  

---

## Usage

```bash
pip install -r requirements.txt
python mbox_to_eml.py
