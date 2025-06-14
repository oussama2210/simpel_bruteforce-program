# WinINet Brute-Force HTTP Login Tool

This project is a multi-threaded brute-force tool for testing HTTP login endpoints on Windows, using the WinINet API. It attempts to find the correct password for a given username by sending HTTP POST requests with credentials from a wordlist.

## Features
- Multi-threaded for speed
- Uses WinINet for HTTP requests
- Customizable target host, path, and wordlist
- Checks for success/failure keywords in the response

## Usage

```
powershell.exe .\brut.exe <host> <path> <wordlist>
```
- `<host>`: The target server (e.g., `example.com`)
- `<path>`: The login endpoint (e.g., `/login.php`)
- `<wordlist>`: Path to a file with passwords (one per line)

**Example:**
```
powershell.exe .\brut.exe example.com /login.php wordlist.txt
```

## Requirements
- Windows OS
- Visual Studio or MinGW for building
- WinINet library (included with Windows SDK)

## Building
Open a Developer Command Prompt and run:
```
cl brut.c /Fe:brut.exe /link wininet.lib ws2_32.lib
```

## Disclaimer
This tool is for educational and authorized testing purposes only. Do not use it on systems you do not own or have explicit permission to test.
