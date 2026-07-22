# Mobisca: Mobile SDK Supply-Chain Risk Scanner

Mobisca is a command-line tool designed to analyze Android APKs for supply-chain risks introduced by third-party SDKs. It assesses various risk factors, including known vulnerabilities, maintenance status, permission scope creep, suspicious native binaries, and communication with known malicious endpoints.

## Features

- **APK Scanning (`scan`)**: Deeply inspects an APK to identify embedded SDKs, evaluating their risk scores based on several heuristics.
- **Supply-Chain Drift Detection (`diff`)**: Compares a baseline APK against a current APK to identify newly added SDKs, removed SDKs, changes in risk scores, and new sensitive permissions requested.
- **JSON Output**: Supports JSON output for easy integration into CI/CD pipelines and automated tooling.
- **Multi-faceted Risk Analysis**:
  - **Vulnerability Scanning**: Checks for known CVEs using the OSV (Open Source Vulnerability) database.
  - **Health and Maintenance**: Queries GitHub to determine if an SDK is actively maintained or abandoned.
  - **Permission Creep**: Identifies if SDKs are requesting excessive or sensitive permissions.
  - **Native Binary Triage (ELF)**: Analyzes native libraries (`.so` files) for packed binaries and suspicious imports.
  - **Network Analysis**: Scans for known malicious endpoints within the app and its SDKs.

## Installation

Ensure you have [Rust and Cargo](https://rustup.rs/) installed. Then, clone the repository and build the project:

```bash
git clone https://github.com/OscarPastry/mobisca
cd mobile-risk-scanner
cargo build --release
```

The executable will be available at `target/release/mobisca`.

## Usage

### 1. Scan an APK

To scan a single APK for SDK risks:

```bash
mobisca scan /path/to/app.apk
```

To output the results in JSON format:

```bash
mobisca scan /path/to/app.apk --json
```

### 2. Diff Two APKs (Drift Detection)

To compare a new version of an app against a baseline version to identify supply-chain drift:

```bash
mobisca diff --baseline /path/to/baseline.apk --current /path/to/current.apk
```

To output the diff report in JSON format:

```bash
mobisca diff --baseline /path/to/baseline.apk --current /path/to/current.apk --json
```

### GitHub API Rate Limits

Mobisca uses the GitHub API to check the maintenance status of identified SDKs. To avoid being rate-limited by GitHub (which happens quickly for unauthenticated requests), it is highly recommended to provide a GitHub Personal Access Token.

You can provide the token via an environment variable or a command-line flag:

**Environment Variable:**

```bash
export GITHUB_TOKEN="your_personal_access_token"
mobisca scan /path/to/app.apk
```

**Command-line Flag:**

```bash
mobisca scan /path/to/app.apk --github-token "your_personal_access_token"
```

## How It Works

Mobisca uses several techniques to statically analyze the provided APK(s):
1. **Manifest Parsing**: Reads the `AndroidManifest.xml` to extract requested permissions and identify components.
2. **DEX Parsing**: Analyzes the Dalvik Executable (`.dex`) files to identify included SDK packages.
3. **Native Library Analysis**: Uses `goblin` to parse ELF binaries, looking for signs of packing or suspicious system calls.
4. **Network Strings**: Extracts and checks URLs against a local blocklist of known malicious or tracking endpoints.
5. **Vulnerability Lookup**: Queries OSV to find reported vulnerabilities associated with the identified SDK versions.

## License

This project is licensed under the terms provided in the repository.
