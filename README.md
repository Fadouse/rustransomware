# Rust Ransomware

## A Rust ransomware framework that bypasses some antivirus solutions e.g. ESET, Avast and Huorong.

**DISCLAIMER: This project is created ONLY for educational and research purposes. Using this code for malicious purposes is illegal and unethical. The author assumes NO responsibility for any misuse of this software.**

## Overview

This project demonstrates a proof-of-concept ransomware implementation in Rust, designed to highlight security vulnerabilities and help researchers understand ransomware mechanics. It is intended for security professionals, penetration testers, and researchers to study encryption techniques and understand how modern ransomware operates.

## Features

- AES-256 CTR mode encryption for target files
- Multi-threaded file encryption using Rayon for parallel processing
- Memory-mapped file operations for efficient file handling
- Selective file targeting based on extensions
- Directory exclusion to avoid system files
- Desktop wallpaper changing capability
- Ransom note generation

## Technical Implementation

- Uses memory mapping for efficient file access
- Implements AES-256 in CTR mode for encryption
- Leverages parallel processing via Rayon
- Employs Windows API for desktop wallpaper modification
- Utilizes random delays to evade behavioral analysis

## Project Structure

- Main encryption logic in `src/main.rs`
- Base64-encoded background image in `src/image.b64`
- Random key and IV generation for each run

## Building

```bash
cargo build --release
```

The compiled binary will be located at `target/release/rustransomware.exe`.

## Usage Notes

This code should ONLY be run in a controlled, isolated environment such as a virtual machine dedicated to malware analysis. Never execute this code on production systems or personal devices.

## Educational Purpose

This project helps security professionals understand:

1. How ransomware identifies and encrypts target files
2. Techniques used to evade detection
3. Implementation of cryptographic algorithms in malicious software
4. Methods for system modification (wallpaper changes, file operations)

## Legal Notice

This software is provided for educational purposes only. The author is not responsible for any damage caused by the misuse of this code. Always obtain proper authorization before conducting security testing.

---

*This project is intended for academic research in cybersecurity. Please use responsibly.*
