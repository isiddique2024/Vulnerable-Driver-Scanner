# Vulnerable-Driver-Scanner

A Python script that scans Windows systems for known vulnerable drivers utilizing the loldrivers.io API, which helps identify potential security threats on your system.

## Overview

Vulnerable-Driver-Scanner helps identify potentially malicious or vulnerable kernel drivers that could be exploited by threat actors. The tool leverages the [loldrivers.io](https://www.loldrivers.io/) database, which is a curated collection of "Living Off The Land Drivers" known to be abused in security attacks.

Malicious actors often use kernel drivers to bypass security controls, disable antivirus software, and gain elevated privileges. This tool helps security professionals detect such drivers present on Windows systems.

## Features

- Scan running drivers currently loaded in the system
- Scan a specified directory path for driver files (.sys)
- Recursive file searching capability
- SHA256 hash verification against known vulnerable drivers
- Simple command-line interface

## Requirements

- Python 3.8+
- Windows operating system
- Internet connection (to fetch the loldrivers.io database)
- PowerShell (for scanning running drivers)

## Installation

1. Clone or download this repository
2. No external Python packages are required (uses standard library)

## Usage

### Scan Running Drivers

To scan all currently running drivers on the system:

```
python vulndriverscan.py -srd true
```

### Scan Directory for Driver Files

To scan a specific directory for vulnerable driver files:

```
python vulndriverscan.py -p "C:\Windows\System32\drivers"
```

### Command Line Arguments

- `-p`, `--path`: Specify a directory path to scan for .sys files
- `-srd`, `--srd`: Set to any value to scan currently running drivers

## How It Works

1. When scanning running drivers, the tool uses PowerShell's `driverquery.exe` to enumerate all loaded drivers
2. For directory scanning, it recursively locates all files with .sys extension
3. The tool calculates SHA256 hashes for each driver file
4. These hashes are compared against known vulnerable drivers from loldrivers.io
5. Any matches are reported as potentially vulnerable

## Example Output

```
scanning running drivers

filepath: C:\Windows\System32\drivers\kmxfw.sys, file hash: 8ee964e3f0f2aa3b5b2c92a67b5de3139a4e7c5ac215d3a08b0060c7348ae348
found a vulnerable driver hash, Filename: kmxfw.sys, Authentihash: 3d6e015840016acf7f5de41c00cf71f1c1b1e1e01b204d3771ef54927610d134
filepath: C:\Windows\System32\drivers\aswArPot.sys, file hash: 9cfd9c7d37657f96df9aa24f432313bfa64b64068b0b5ded5d7dd5fc3f936471
vuln driver hash not found for C:\Windows\System32\drivers\aswArPot.sys
```

## Security Considerations

- This tool requires access to driver files, which may require administrative privileges
- Only use this tool on systems you own or have permission to scan
- False positives may occur, as legitimate drivers may share names with vulnerable ones
- The tool only identifies known vulnerable drivers; unknown vulnerabilities won't be detected

## Acknowledgments

- This tool uses the loldrivers.io API, which is maintained by [MagicSword-io](https://github.com/magicsword-io/LOLDrivers)
- LOLDrivers.io is a community-driven project documenting Windows drivers used by adversaries

## License

This project is open source and available under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
