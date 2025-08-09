# Betanet v1.1 Specification Compliance Linter

A comprehensive command-line tool to validate Betanet implementations against the official v1.1 specification requirements. This linter automatically checks all 11 mandatory compliance requirements from § 11 of the spec and generates detailed reports with Software Bill of Materials (SBOM).

## 🚀 Features

- **Complete Spec Coverage**: Validates all 11 requirements from § 11 Compliance Summary
- **Automated Testing**: Run against any Betanet binary implementation
- **Detailed Reports**: Text and JSON output formats with evidence tracking
- **SBOM Generation**: CycloneDX-compatible Software Bill of Materials
- **CI/CD Integration**: Ready-made GitHub Action workflow template
- **Security Focus**: Validates cryptographic primitives and security requirements
- **Cross-Platform**: Works on Linux, macOS, and Windows

## 📋 Compliance Requirements Checked

| ID | Section | Requirement | Description |
|---|---|---|---|
| 1 | §5.1, §5.6 | HTX Transport | TCP-443/QUIC-443 with origin-mirrored TLS + ECH |
| 2 | §5.2 | Access Tickets | Negotiated-carrier, replay-bound tickets |
| 3 | §5.3 | Noise Handshake | Inner Noise XK with PQ hybrid from 2027-01-01 |
| 4 | §5.5 | HTTP Emulation | HTTP/2/3 adaptive cadences |
| 5 | §4.2 | SCION Bridging | HTX-tunnelled transition |
| 6 | §6.2 | Transport Protocols | `/betanet/htx/1.1.0` and `/betanet/htxquic/1.1.0` |
| 7 | §6.3, §6.5 | Bootstrap Discovery | Rotating rendezvous with PoW |
| 8 | §7.1, §7.2 | Mixnet Selection | BeaconSet randomness with diversity |
| 9 | §8.2 | Alias Ledger | Finality-bound 2-of-3 with liveness |
| 10 | §9.1, §9.2 | Cashu Vouchers | 128-B vouchers with Lightning settlement |
| 11 | §10.2, §10.3 | Governance | Anti-concentration caps and diversity |
| 12 | §5.6 | Anti-Correlation | Fallback with cover connections |
| 13 | §11 | Build Provenance | Reproducible builds with SLSA 3 |

## 🛠 Installation

### Prerequisites

- Python 3.9+
- System tools: `ldd` (Linux), `otool` (macOS), `strings`
- Target Betanet binary to test

### Quick Install

```bash
# Download the linter
curl -L -O https://raw.githubusercontent.com/your-org/betanet-linter/main/betanet_linter.py
chmod +x betanet_linter.py

# Verify installation
python betanet_linter.py --help
```

### From Source

```bash
git clone https://github.com/your-org/betanet-linter.git
cd betanet-linter
python -m pip install -r requirements.txt
```

## 📖 Usage

### Basic Usage

```bash
# Run compliance check on binary
python betanet_linter.py --binary ./your-betanet-node

# JSON output with file save
python betanet_linter.py --binary ./your-betanet-node --output json --report-file report.json

# Generate SBOM separately
python betanet_linter.py --binary ./your-betanet-node --sbom-file sbom.json

# Verbose output for debugging
python betanet_linter.py --binary ./your-betanet-node --verbose
```

### Advanced Usage

```bash
# Use custom configuration
python betanet_linter.py --binary ./betanet-node --config config.json

# Generate GitHub Action workflow
python betanet_linter.py --generate-github-action > .github/workflows/compliance.yml
```

## ⚙️ Configuration

Create a `config.json` file to customize the linter behavior:

```json
{
  "timeout": 30,
  "test_host": "localhost",
  "test_port": 8443,
  "strict_mode": false,
  "skip_checks": [],
  "custom_checks": {
    "enable_experimental": false,
    "additional_ports": [443, 8080],
    "crypto_validation_level": "standard"
  },
  "output_settings": {
    "max_evidence_items": 5,
    "include_debug_info": false,
    "compact_sbom": true
  }
}
```

### Configuration Options

| Option | Default | Description |
|---|---|---|
| `timeout` | 30 | Command timeout in seconds |
| `test_host` | "localhost" | Host for connectivity tests |
| `test_port` | 8443 | Port for binding tests |
| `strict_mode` | false | Fail on warnings |
| `skip_checks` | [] | List of check IDs to skip |

## 📊 Report Formats

### Text Output

```
================================================================================
BETANET v1.1 SPECIFICATION COMPLIANCE REPORT
================================================================================
Binary: /path/to/betanet-node
Test Date: 2025-01-15T10:30:45.123456+00:00
Betanet Version: 1.1

SUMMARY:
  Total Requirements: 13
  ✅ Passed: 10
  ❌ Failed: 2
  ⚠️  Warnings: 1
  ⏭️  Skipped: 0

Compliance Score: 76.9%

DETAILED RESULTS:
--------------------------------------------------------------------------------
✅ HTX TRANSPORT (§5.1, §5.6)
   Description: HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH
   Status: PASS
   Details: HTX transport protocols appear to be supported
   Evidence:
     • TCP support detected: True
     • QUIC support detected: True
     • TLS support detected: True
...
```

### JSON Output

```json
{
  "binary_path": "/path/to/betanet-node",
  "test_timestamp": "2025-01-15T10:30:45.123456+00:00",
  "betanet_version": "1.1",
  "total_requirements": 13,
  "passed": 10,
  "failed": 2,
  "warnings": 1,
  "skipped": 0,
  "results": [
    {
      "requirement_id": "htx_transport",
      "description": "HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH",
      "status": "PASS",
      "details": "HTX transport protocols appear to be supported",
      "evidence": ["TCP support detected: True", "QUIC support detected: True"],
      "section_ref": "§5.1, §5.6"
    }
  ],
  "sbom": [
    {
      "name": "betanet-node",
      "version": "unknown",
      "type": "application",
      "supplier": "unknown",
      "hash": "sha256:abc123..."
    }
  ]
}
```

## 🔄 CI/CD Integration

### GitHub Actions

The linter includes a ready-made GitHub Action workflow. Generate it with:

```bash
python betanet_linter.py --generate-github-action > .github/workflows/betanet-compliance.yml
```

Key features of the GitHub Action:
- Runs on push, PR, and releases
- Comments on PRs with compliance results
- Uploads compliance reports as artifacts
- Sets commit status checks
- Supports custom build processes

### GitLab CI

```yaml
betanet-compliance:
  stage: test
  image: python:3.9
  script:
    - curl -L -O https://raw.githubusercontent.com/your-org/betanet-linter/main/betanet_linter.py
    - python betanet_linter.py --binary ./betanet-node --output json --report-file compliance-report.json
  artifacts:
    reports:
      junit: compliance-report.json
    paths:
      - compliance-report.json
      - sbom.json
  only:
    - merge_requests
    - main
```

## 🧪 Testing Your Implementation

### Development Checklist

Before running the linter, ensure your Betanet implementation:

1. **Builds Successfully**: Can compile and run without errors
2. **Supports Help Commands**: Responds to `--help`, `--version` flags
3. **Network Binding**: Can attempt to bind to network ports
4. **Protocol Support**: Includes required transport protocols
5. **Configuration**: Supports configuration options

### Common Issues

| Issue | Likely Cause | Solution |
|---|---|---|
| "BINARY_NOT_FOUND" | Path incorrect or binary not executable | Check path and permissions |
| Multiple "WARN" status | Limited introspection capabilities | Normal for static analysis |
| "TIMEOUT" errors | Binary hangs on startup | Check binary dependencies |
| Crypto detection fails | Statically linked libraries | Expected, check manual verification |

## 🔍 Understanding Results

### Status Meanings

- **PASS** ✅: Requirement fully satisfied with evidence
- **FAIL** ❌: Requirement clearly not met or critical issue found
- **WARN** ⚠️: Partial compliance or unable to verify fully
- **SKIP** ⏭️: Check skipped due to configuration or dependencies

### Compliance Scoring

| Score | Level | Description |
|---|---|---|
| 90-100% | Excellent | Production-ready, full compliance |
| 75-89% | Good | Minor issues, mostly compliant |
| 50-74% | Moderate | Significant gaps, needs work |
| 0-49% | Poor | Major compliance issues |

### Critical vs Non-Critical

Critical requirements (failures block CI):
- HTX Transport
- Noise Handshake with PQ support (from 2027)
- Transport Protocol support
- Access Tickets

Non-critical (warnings only):
- Build provenance (development phase)
- Some bootstrap methods
- Advanced governance features

## 🛡️ Security Considerations

The linter validates several security-critical aspects:

1. **Cryptographic Primitives**: Ensures required crypto (ChaCha20-Poly1305, Ed25519, X25519, Kyber768)
2. **Post-Quantum Readiness**: Checks for Kyber768 support (mandatory from 2027-01-01)
3. **Transport Security**: Validates TLS configuration and ECH support
4. **Access Control**: Verifies ticket-based authentication
5. **Anti-Correlation**: Checks fallback mechanisms

## 🤝 Contributing

We welcome contributions to improve the linter:

1. **Bug Reports**: Use GitHub issues for bugs
2. **Feature Requests**: Suggest new compliance checks
3. **Pull Requests**: Follow the contribution guidelines
4. **Documentation**: Help improve docs and examples

### Development Setup

```bash
git clone https://github.com/your-org/betanet-linter.git
cd betanet-linter
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements-dev.txt
pre-commit install
```

### Running Tests

```bash
# Unit tests
python -m pytest tests/

# Integration tests
python -m pytest tests/integration/

# Test against reference implementation
./scripts/test-reference-impl.sh
```

## 📚 Reference Materials

- [Betanet v1.1 Official Specification](https://spec.betanet.org/v1.1/)
- [SCION Architecture](https://scion-architecture.net/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Nym Mixnet Documentation](https://nymtech.net/docs/)
- [Cashu Protocol](https://cashubtc.github.io/nuts/)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check this README and inline help
- **Issues**: Use GitHub issues for bug reports
- **Discussions**: Use GitHub discussions for questions
- **Security**: Send security issues to security@your-org.com

## 🔄 Changelog

### v1.1.0 (Current)
- Full Betanet v1.1 specification support
- All 13 compliance requirements implemented
- SBOM generation with CycloneDX format
- GitHub Action integration
- Post-quantum cryptography validation

### v1.0.0
- Initial release
- Basic compliance checking
- Text and JSON output formats

---

## Configuration File Template

Save this as `config.json` for custom configuration:

```json
{
  "timeout": 30,
  "test_host": "localhost", 
  "test_port": 8443,
  "strict_mode": false,
  "skip_checks": [],
  "custom_checks": {
    "enable_experimental": false,
    "additional_ports": [443, 8080, 9443],
    "crypto_validation_level": "standard",
    "require_slsa_provenance": false
  },
  "output_settings": {
    "max_evidence_items": 5,
    "include_debug_info": false,
    "compact_sbom": true,
    "show_skipped_details": false
  },
  "network_tests": {
    "enable_connectivity_tests": false,
    "test_external_hosts": ["example.com", "google.com"],
    "connection_timeout": 5
  },
  "binary_analysis": {
    "deep_dependency_scan": true,
    "extract_build_info": true,
    "verify_signatures": false
  },
  "compliance_thresholds": {
    "minimum_pass_score": 75,
    "warning_threshold": 85,
    "fail_on_critical_missing": true
  }
}
```

## Environment Variables

The linter supports these environment variables:

```bash
# Override default configuration
export BETANET_LINTER_CONFIG="/path/to/config.json"

# Set verbosity level
export BETANET_LINTER_VERBOSE=1

# Skip network tests in CI
export BETANET_LINTER_SKIP_NETWORK=1

# Custom timeout
export BETANET_LINTER_TIMEOUT=60

# Test mode (less strict validation)
export BETANET_LINTER_TEST_MODE=1
```

**Ready to validate your Betanet implementation? Start with:**

```bash
python betanet_linter.py --binary ./your-betanet-binary --verbose
```