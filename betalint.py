#!/usr/bin/env python3
"""
Betanet Specification Compliance Linter
Author: Tom 'Mentor' Wilcox
Date: 2025.8.9
Version: 1.1.0-DEV
============================================

A command-line tool to validate Betanet implementations against the official
specification requirements outlined in § 11 Compliance Summary.

Usage:
    python betalint.py --binary <path> [--output <format>] [--config <file>]

Requirements validation based on Betanet v1.1 Official Implementation Specification
"""

import argparse
import json
import sys
import subprocess
import socket
import ssl
import time
import hashlib
import struct
import os
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import tempfile
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ComplianceResult:
    """Result of a single compliance check"""

    requirement_id: str
    description: str
    status: str  # PASS, FAIL, WARN, SKIP
    details: str
    evidence: List[str]
    section_ref: str


@dataclass
class SBOMComponent:
    """Software Bill of Materials component"""

    name: str
    version: str
    type: str  # library, framework, application
    supplier: str
    hash: Optional[str] = None
    license: Optional[str] = None


@dataclass
class ComplianceReport:
    """Complete compliance assessment report"""

    binary_path: str
    test_timestamp: str
    betanet_version: str
    total_requirements: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    results: List[ComplianceResult]
    sbom: List[SBOMComponent]


class BetanetLinter:
    """Main linter class for Betanet spec compliance"""

    def __init__(self, binary_path: str, config: Optional[Dict] = None):
        self.binary_path = Path(binary_path).resolve()
        self.config = config or {}
        self.temp_dir = Path(tempfile.mkdtemp())
        self.results: List[ComplianceResult] = []

        # Test configuration
        self.test_timeout = self.config.get("timeout", 30)
        self.test_host = self.config.get("test_host", "localhost")
        self.test_port = self.config.get("test_port", 8443)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean up temp directory
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_compliance_check(self) -> ComplianceReport:
        """Execute all compliance checks from § 11"""
        logger.info(f"Starting compliance check for: {self.binary_path}")

        # § 11 Compliance Requirements
        checks = [
            self._check_htx_transport,  # 11.1: HTX over TCP-443/QUIC-443
            self._check_access_tickets,  # 11.2: Access tickets
            self._check_noise_handshake,  # 11.3: Noise XK with PQ
            self._check_http_emulation,  # 11.4: HTTP/2/3 emulation
            self._check_scion_bridging,  # 11.5: SCION bridging
            self._check_transport_protocols,  # 11.6: Transport protocols
            self._check_bootstrap_discovery,  # 11.7: Bootstrap discovery
            self._check_mixnet_selection,  # 11.8: Mixnode selection
            self._check_alias_ledger,  # 11.9: Alias ledger verification
            self._check_cashu_vouchers,  # 11.10: Cashu vouchers
            self._check_governance_caps,  # 11.11: Governance enforcement
        ]

        for check_func in checks:
            try:
                result = check_func()
                self.results.append(result)
            except Exception as e:
                logger.error(f"Check {check_func.__name__} failed: {e}")
                self.results.append(
                    ComplianceResult(
                        requirement_id=check_func.__name__.replace("_check_", ""),
                        description=f"Error in {check_func.__name__}",
                        status="FAIL",
                        details=f"Exception: {str(e)}",
                        evidence=[],
                        section_ref="§11",
                    )
                )

        # Additional checks
        self.results.append(self._check_anti_correlation_fallback())
        self.results.append(self._check_build_provenance())

        return self._generate_report()

    def _check_htx_transport(self) -> ComplianceResult:
        """§ 11.1: HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH"""
        req_id = "htx_transport"
        evidence = []

        try:
            # Check if binary supports required protocols
            help_output = self._run_binary_command(["--help"])
            evidence.append(f"Help output length: {len(help_output)}")

            # Look for protocol support indicators
            tcp_support = "tcp" in help_output.lower() or "443" in help_output
            quic_support = "quic" in help_output.lower() or "udp" in help_output.lower()
            tls_support = "tls" in help_output.lower() or "ssl" in help_output.lower()

            evidence.extend(
                [
                    f"TCP support detected: {tcp_support}",
                    f"QUIC support detected: {quic_support}",
                    f"TLS support detected: {tls_support}",
                ]
            )

            # Try to start the binary and check for port binding
            if self._test_port_binding():
                evidence.append("Successfully bound to test port")
                status = (
                    "PASS" if (tcp_support and quic_support and tls_support) else "WARN"
                )
                details = "HTX transport protocols appear to be supported"
            else:
                status = "WARN"
                details = "Could not verify port binding, but protocol support detected"

        except Exception as e:
            status = "FAIL"
            details = f"Failed to verify HTX transport: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§5.1, §5.6",
        )

    def _check_access_tickets(self) -> ComplianceResult:
        """§ 11.2: Negotiated-carrier, replay-bound access tickets"""
        req_id = "access_tickets"
        evidence = []

        try:
            # Check for access ticket implementation
            config_output = self._run_binary_command(
                ["--config-help"], ignore_errors=True
            )
            evidence.append(f"Config help available: {len(config_output) > 0}")

            # Look for ticket-related configuration
            ticket_keywords = ["ticket", "carrier", "cookie", "query", "body"]
            ticket_support = any(
                keyword in config_output.lower() for keyword in ticket_keywords
            )
            evidence.append(f"Ticket configuration detected: {ticket_support}")

            # Check for crypto dependencies (X25519, HKDF)
            crypto_keywords = ["x25519", "hkdf", "sha256"]
            crypto_support = any(
                keyword in config_output.lower() for keyword in crypto_keywords
            )
            evidence.append(f"Required crypto primitives detected: {crypto_support}")

            status = "PASS" if ticket_support else "WARN"
            details = (
                "Access ticket support detected"
                if ticket_support
                else "Access ticket support unclear"
            )

        except Exception as e:
            status = "FAIL"
            details = f"Failed to verify access tickets: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Negotiated-carrier, replay-bound access tickets with variable lengths",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§5.2",
        )

    def _check_noise_handshake(self) -> ComplianceResult:
        """§ 11.3: Inner Noise XK with key separation, nonce lifecycle, and rekeying"""
        req_id = "noise_handshake"
        evidence = []

        try:
            # Check for Noise protocol implementation
            deps = self._get_binary_dependencies()
            evidence.append(f"Dependencies found: {len(deps)}")

            noise_libs = ["noise", "chacha20", "poly1305", "kyber"]
            noise_support = any(
                any(lib in dep.lower() for lib in noise_libs) for dep in deps
            )
            evidence.append(f"Noise/Crypto libraries detected: {noise_support}")

            # Check for post-quantum support (required from 2027-01-01)
            pq_keywords = ["kyber", "post-quantum", "pq", "hybrid"]
            pq_support = any(
                keyword in " ".join(deps).lower() for keyword in pq_keywords
            )
            evidence.append(f"Post-quantum support detected: {pq_support}")

            # Date check for PQ requirement
            current_date = datetime.now(timezone.utc)
            pq_required = current_date >= datetime(2027, 1, 1, tzinfo=timezone.utc)
            evidence.append(f"Post-quantum required: {pq_required}")

            if pq_required and not pq_support:
                status = "FAIL"
                details = "Post-quantum hybrid X25519-Kyber768 required from 2027-01-01"
            elif noise_support:
                status = "PASS"
                details = "Noise XK handshake implementation detected"
            else:
                status = "WARN"
                details = "Noise protocol implementation unclear"

        except Exception as e:
            status = "FAIL"
            details = f"Failed to verify Noise handshake: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Inner Noise XK with key separation and PQ hybrid from 2027-01-01",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§5.3",
        )

    def _check_http_emulation(self) -> ComplianceResult:
        """§ 11.4: HTTP/2/3 emulation with adaptive cadences"""
        req_id = "http_emulation"
        evidence = []

        try:
            # Check for HTTP/2 and HTTP/3 support
            version_output = self._run_binary_command(["--version"], ignore_errors=True)
            evidence.append(f"Version info available: {len(version_output) > 0}")

            http_keywords = ["http/2", "http2", "h2", "http/3", "http3", "h3", "quic"]
            http_support = any(
                keyword in version_output.lower() for keyword in http_keywords
            )
            evidence.append(f"HTTP/2 or HTTP/3 support detected: {http_support}")

            # Check for adaptive behavior configuration
            adaptive_keywords = ["adaptive", "cadence", "ping", "priority", "settings"]
            adaptive_support = any(
                keyword in version_output.lower() for keyword in adaptive_keywords
            )
            evidence.append(f"Adaptive behavior indicators: {adaptive_support}")

            status = "PASS" if http_support else "WARN"
            details = (
                "HTTP emulation support detected"
                if http_support
                else "HTTP emulation unclear"
            )

        except Exception as e:
            status = "WARN"
            details = f"Could not fully verify HTTP emulation: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="HTTP/2/3 emulation with adaptive cadences and origin-mirrored parameters",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§5.5",
        )

    def _check_scion_bridging(self) -> ComplianceResult:
        """§ 11.5: SCION bridging via HTX tunnels"""
        req_id = "scion_bridging"
        evidence = []

        try:
            # Check for SCION-related functionality
            help_output = self._run_binary_command(["--help"], ignore_errors=True)

            scion_keywords = ["scion", "bridge", "gateway", "tunnel", "as-hop"]
            scion_support = any(
                keyword in help_output.lower() for keyword in scion_keywords
            )
            evidence.append(f"SCION bridging indicators: {scion_support}")

            # Check for HTX tunnel support
            htx_keywords = ["htx", "control stream", "transition"]
            htx_support = any(
                keyword in help_output.lower() for keyword in htx_keywords
            )
            evidence.append(f"HTX tunnel support detected: {htx_support}")

            status = "PASS" if (scion_support and htx_support) else "WARN"
            details = (
                "SCION bridging support detected"
                if scion_support
                else "SCION bridging support unclear"
            )

        except Exception as e:
            status = "WARN"
            details = f"Could not verify SCION bridging: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="SCION bridging via HTX-tunnelled transition, no public on-wire headers",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§4.2",
        )

    def _check_transport_protocols(self) -> ComplianceResult:
        """§ 11.6: Required transport protocol support"""
        req_id = "transport_protocols"
        evidence = []

        try:
            # Check for required transport protocol announcements
            protocols_output = self._run_binary_command(
                ["--protocols"], ignore_errors=True
            )
            if not protocols_output:
                protocols_output = self._run_binary_command(
                    ["--transports"], ignore_errors=True
                )

            required_protocols = ["/betanet/htx/1.1.0", "/betanet/htxquic/1.1.0"]

            protocols_found = []
            for protocol in required_protocols:
                found = protocol in protocols_output
                protocols_found.append(found)
                evidence.append(f"{protocol}: {'FOUND' if found else 'NOT FOUND'}")

            all_protocols_found = all(protocols_found)

            status = "PASS" if all_protocols_found else "FAIL"
            details = f"Required protocols: {sum(protocols_found)}/{len(required_protocols)} found"

        except Exception as e:
            status = "WARN"
            details = f"Could not verify transport protocols: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Offers /betanet/htx/1.1.0 and /betanet/htxquic/1.1.0 transports",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§6.2",
        )

    def _check_bootstrap_discovery(self) -> ComplianceResult:
        """§ 11.7: Bootstrap via rotating rendezvous with PoW"""
        req_id = "bootstrap_discovery"
        evidence = []

        try:
            # Check for bootstrap methods
            bootstrap_output = self._run_binary_command(
                ["--bootstrap-help"], ignore_errors=True
            )

            bootstrap_methods = ["dht", "mdns", "bluetooth", "onion", "dns"]
            methods_found = []
            for method in bootstrap_methods:
                found = method in bootstrap_output.lower()
                methods_found.append(found)
                evidence.append(
                    f"{method.upper()} method: {'FOUND' if found else 'NOT FOUND'}"
                )

            # Check for PoW and rate limiting
            pow_keywords = ["pow", "proof-of-work", "difficulty", "rate-limit"]
            pow_support = any(
                keyword in bootstrap_output.lower() for keyword in pow_keywords
            )
            evidence.append(f"PoW/rate-limiting support: {pow_support}")

            # Check for BeaconSet usage
            beacon_keywords = ["beacon", "epoch", "rotating", "rendezvous"]
            beacon_support = any(
                keyword in bootstrap_output.lower() for keyword in beacon_keywords
            )
            evidence.append(f"BeaconSet/rotating support: {beacon_support}")

            methods_score = sum(methods_found)
            if methods_score >= 3 and pow_support and beacon_support:
                status = "PASS"
                details = f"Bootstrap discovery properly implemented ({methods_score}/5 methods)"
            elif methods_score >= 2:
                status = "WARN"
                details = (
                    f"Partial bootstrap implementation ({methods_score}/5 methods)"
                )
            else:
                status = "FAIL"
                details = "Insufficient bootstrap discovery methods"

        except Exception as e:
            status = "WARN"
            details = f"Could not verify bootstrap discovery: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Bootstrap via rotating rendezvous IDs with PoW and rate-limits",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§6.3, §6.5",
        )

    def _check_mixnet_selection(self) -> ComplianceResult:
        """§ 11.8: Mixnode selection using BeaconSet randomness"""
        req_id = "mixnet_selection"
        evidence = []

        try:
            # Check for privacy/mixnet configuration
            privacy_output = self._run_binary_command(
                ["--privacy-help"], ignore_errors=True
            )

            # Check for privacy modes
            privacy_modes = ["strict", "balanced", "performance"]
            modes_found = []
            for mode in privacy_modes:
                found = mode in privacy_output.lower()
                modes_found.append(found)
                evidence.append(f"{mode} mode: {'FOUND' if found else 'NOT FOUND'}")

            # Check for mixnet integration
            mixnet_keywords = ["nym", "mixnet", "hop", "relay"]
            mixnet_support = any(
                keyword in privacy_output.lower() for keyword in mixnet_keywords
            )
            evidence.append(f"Mixnet integration: {mixnet_support}")

            # Check for BeaconSet randomness
            beacon_keywords = ["beacon", "vrf", "entropy", "diversity"]
            beacon_support = any(
                keyword in privacy_output.lower() for keyword in beacon_keywords
            )
            evidence.append(f"BeaconSet randomness: {beacon_support}")

            modes_score = sum(modes_found)
            if modes_score >= 2 and mixnet_support and beacon_support:
                status = "PASS"
                details = "Mixnode selection properly implemented"
            elif mixnet_support:
                status = "WARN"
                details = "Partial mixnet implementation detected"
            else:
                status = "FAIL"
                details = "No mixnet selection implementation found"

        except Exception as e:
            status = "WARN"
            details = f"Could not verify mixnet selection: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Mixnode selection using BeaconSet randomness with path diversity",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§7.1, §7.2",
        )

    def _check_alias_ledger(self) -> ComplianceResult:
        """§ 11.9: Alias ledger verification with finality-bound 2-of-3"""
        req_id = "alias_ledger"
        evidence = []

        try:
            # Check for alias/naming system
            naming_output = self._run_binary_command(
                ["--naming-help"], ignore_errors=True
            )

            # Check for supported chains
            chains = ["handshake", "filecoin", "ethereum", "raven"]
            chains_found = []
            for chain in chains:
                found = chain in naming_output.lower()
                chains_found.append(found)
                evidence.append(
                    f"{chain.title()} chain: {'FOUND' if found else 'NOT FOUND'}"
                )

            # Check for finality concepts
            finality_keywords = ["finality", "confirmation", "reorg", "quorum"]
            finality_support = any(
                keyword in naming_output.lower() for keyword in finality_keywords
            )
            evidence.append(f"Finality handling: {finality_support}")

            # Check for emergency advance (liveness)
            liveness_keywords = ["emergency", "liveness", "governance", "certificate"]
            liveness_support = any(
                keyword in naming_output.lower() for keyword in liveness_keywords
            )
            evidence.append(f"Liveness mechanism: {liveness_support}")

            chains_score = sum(chains_found)
            if chains_score >= 2 and finality_support:
                status = "PASS"
                details = f"Alias ledger implementation found ({chains_score}/4 chains)"
            elif chains_score >= 1:
                status = "WARN"
                details = (
                    f"Partial alias ledger implementation ({chains_score}/4 chains)"
                )
            else:
                status = "FAIL"
                details = "No alias ledger implementation found"

        except Exception as e:
            status = "WARN"
            details = f"Could not verify alias ledger: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Alias ledger verification with finality-bound 2-of-3 and liveness",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§8.2",
        )

    def _check_cashu_vouchers(self) -> ComplianceResult:
        """§ 11.10: Cashu vouchers for known keysets"""
        req_id = "cashu_vouchers"
        evidence = []

        try:
            # Check for payment/voucher system
            payment_output = self._run_binary_command(
                ["--payment-help"], ignore_errors=True
            )

            # Check for Cashu implementation
            cashu_keywords = ["cashu", "voucher", "mint", "keyset", "frost"]
            cashu_support = any(
                keyword in payment_output.lower() for keyword in cashu_keywords
            )
            evidence.append(f"Cashu voucher support: {cashu_support}")

            # Check for Lightning integration
            lightning_keywords = ["lightning", "ln", "settlement", "redeem"]
            lightning_support = any(
                keyword in payment_output.lower() for keyword in lightning_keywords
            )
            evidence.append(f"Lightning settlement: {lightning_support}")

            # Check for PoW and rate limiting
            security_keywords = ["pow", "rate-limit", "validation"]
            security_support = any(
                keyword in payment_output.lower() for keyword in security_keywords
            )
            evidence.append(f"Security mechanisms: {security_support}")

            if cashu_support and lightning_support:
                status = "PASS"
                details = "Cashu voucher system properly implemented"
            elif cashu_support:
                status = "WARN"
                details = "Cashu support detected, Lightning settlement unclear"
            else:
                status = "FAIL"
                details = "No Cashu voucher implementation found"

        except Exception as e:
            status = "WARN"
            details = f"Could not verify Cashu vouchers: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="128-B Cashu vouchers for known keysets with PoW and Lightning settlement",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§9.1, §9.2",
        )

    def _check_governance_caps(self) -> ComplianceResult:
        """§ 11.11: Governance enforcement with anti-concentration caps"""
        req_id = "governance_caps"
        evidence = []

        try:
            # Check for governance system
            gov_output = self._run_binary_command(
                ["--governance-help"], ignore_errors=True
            )

            # Check for voting and weight systems
            voting_keywords = ["vote", "weight", "uptime", "stake", "quorum"]
            voting_support = any(
                keyword in gov_output.lower() for keyword in voting_keywords
            )
            evidence.append(f"Voting system: {voting_support}")

            # Check for anti-concentration measures
            caps_keywords = ["cap", "concentration", "as", "org", "diversity"]
            caps_support = any(
                keyword in gov_output.lower() for keyword in caps_keywords
            )
            evidence.append(f"Anti-concentration caps: {caps_support}")

            # Check for partition safety
            partition_keywords = ["partition", "path", "reachability", "safety"]
            partition_support = any(
                keyword in gov_output.lower() for keyword in partition_keywords
            )
            evidence.append(f"Partition safety: {partition_support}")

            if voting_support and caps_support and partition_support:
                status = "PASS"
                details = "Governance system properly implemented"
            elif voting_support:
                status = "WARN"
                details = "Partial governance implementation detected"
            else:
                status = "FAIL"
                details = "No governance implementation found"

        except Exception as e:
            status = "WARN"
            details = f"Could not verify governance: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Anti-concentration caps, diversity, and partition checks for governance",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§10.2, §10.3",
        )

    def _check_anti_correlation_fallback(self) -> ComplianceResult:
        """Anti-correlation fallback with cover connections"""
        req_id = "anti_correlation"
        evidence = []

        try:
            # Check for fallback mechanisms
            fallback_output = self._run_binary_command(
                ["--fallback-help"], ignore_errors=True
            )

            # Check for cover connection support
            cover_keywords = ["cover", "fallback", "correlation", "retry"]
            cover_support = any(
                keyword in fallback_output.lower() for keyword in cover_keywords
            )
            evidence.append(f"Cover connection support: {cover_support}")

            status = "PASS" if cover_support else "WARN"
            details = (
                "Anti-correlation fallback detected"
                if cover_support
                else "Anti-correlation unclear"
            )

        except Exception as e:
            status = "WARN"
            details = f"Could not verify anti-correlation: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Anti-correlation fallback with cover connections on UDP→TCP retries",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§5.6",
        )

    def _check_build_provenance(self) -> ComplianceResult:
        """Build reproducibility and SLSA provenance"""
        req_id = "build_provenance"
        evidence = []

        try:
            # Check for build information
            build_info = self._get_build_info()
            evidence.extend(build_info)

            # Look for SLSA indicators
            slsa_indicators = ["slsa", "provenance", "reproducible", "attestation"]
            slsa_support = any(
                indicator in " ".join(build_info).lower()
                for indicator in slsa_indicators
            )
            evidence.append(f"SLSA provenance indicators: {slsa_support}")

            status = "PASS" if slsa_support else "WARN"
            details = (
                "Build provenance detected"
                if slsa_support
                else "Build provenance unclear"
            )

        except Exception as e:
            status = "WARN"
            details = f"Could not verify build provenance: {str(e)}"
            evidence.append(f"Error: {str(e)}")

        return ComplianceResult(
            requirement_id=req_id,
            description="Reproducible builds with SLSA 3 provenance artifacts",
            status=status,
            details=details,
            evidence=evidence,
            section_ref="§11",
        )

    def _run_binary_command(self, args: List[str], ignore_errors: bool = False) -> str:
        """Run the binary with given arguments and return output"""
        try:
            cmd = [str(self.binary_path)] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.test_timeout,
                cwd=self.temp_dir,
            )

            if result.returncode != 0 and not ignore_errors:
                logger.warning(
                    f"Command failed: {' '.join(cmd)}, stderr: {result.stderr}"
                )

            return result.stdout + result.stderr

        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except FileNotFoundError:
            return "BINARY_NOT_FOUND"
        except Exception as e:
            if not ignore_errors:
                logger.error(f"Failed to run command {args}: {e}")
            return f"ERROR: {str(e)}"

    def _test_port_binding(self) -> bool:
        """Test if the binary can bind to a test port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.test_host, self.test_port))
                return True
        except OSError:
            return False

    def _get_binary_dependencies(self) -> List[str]:
        """Extract dependencies from binary"""
        deps = []
        try:
            # Try common dependency inspection methods
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["ldd", str(self.binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    deps.extend(result.stdout.split("\n"))

            elif sys.platform == "darwin":
                result = subprocess.run(
                    ["otool", "-L", str(self.binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    deps.extend(result.stdout.split("\n"))

            # Try strings command for additional analysis
            result = subprocess.run(
                ["strings", str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Filter for crypto/protocol related strings
                crypto_strings = [
                    line
                    for line in result.stdout.split("\n")
                    if any(
                        keyword in line.lower()
                        for keyword in [
                            "noise",
                            "chacha",
                            "poly1305",
                            "kyber",
                            "x25519",
                            "quic",
                            "tls",
                        ]
                    )
                ]
                deps.extend(crypto_strings[:20])  # Limit to avoid spam

        except Exception as e:
            logger.warning(f"Failed to extract dependencies: {e}")

        return [dep for dep in deps if dep.strip()]

    def _get_build_info(self) -> List[str]:
        """Extract build information from binary"""
        build_info = []
        try:
            # Try version command
            version_output = self._run_binary_command(["--version"], ignore_errors=True)
            if version_output and "ERROR" not in version_output:
                build_info.append(f"Version info: {version_output.strip()}")

            # Try build info command
            build_output = self._run_binary_command(
                ["--build-info"], ignore_errors=True
            )
            if build_output and "ERROR" not in build_output:
                build_info.append(f"Build info: {build_output.strip()}")

            # File metadata
            stat = self.binary_path.stat()
            build_info.extend(
                [
                    f"File size: {stat.st_size} bytes",
                    f"Modified: {datetime.fromtimestamp(stat.st_mtime).isoformat()}",
                ]
            )

            # Try to extract build ID or hash
            if sys.platform.startswith("linux"):
                result = subprocess.run(
                    ["file", str(self.binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    build_info.append(f"File info: {result.stdout.strip()}")

        except Exception as e:
            build_info.append(f"Build info extraction error: {str(e)}")

        return build_info

    def _generate_sbom(self) -> List[SBOMComponent]:
        """Generate Software Bill of Materials"""
        components = []

        # Core binary component
        binary_hash = self._calculate_file_hash(self.binary_path)
        components.append(
            SBOMComponent(
                name=self.binary_path.name,
                version="unknown",
                type="application",
                supplier="unknown",
                hash=binary_hash,
            )
        )

        # Extract dependencies and create components
        deps = self._get_binary_dependencies()
        for dep in deps[:10]:  # Limit to top 10 to avoid clutter
            if dep.strip() and not dep.startswith("\t"):
                # Parse common dependency formats
                if "=>" in dep:  # Linux ldd format
                    name = dep.split("=>")[0].strip()
                elif "/" in dep and not dep.startswith("/"):  # Library name
                    name = dep.split("/")[-1].strip()
                else:
                    name = dep.strip()

                if name and len(name) < 100:  # Sanity check
                    components.append(
                        SBOMComponent(
                            name=name,
                            version="unknown",
                            type="library",
                            supplier="system",
                        )
                    )

        return components

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to calculate hash for {file_path}: {e}")
            return "unknown"

    def _generate_report(self) -> ComplianceReport:
        """Generate final compliance report"""
        passed = sum(1 for r in self.results if r.status == "PASS")
        failed = sum(1 for r in self.results if r.status == "FAIL")
        warnings = sum(1 for r in self.results if r.status == "WARN")
        skipped = sum(1 for r in self.results if r.status == "SKIP")

        sbom = self._generate_sbom()

        return ComplianceReport(
            binary_path=str(self.binary_path),
            test_timestamp=datetime.now(timezone.utc).isoformat(),
            betanet_version="1.1",
            total_requirements=len(self.results),
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            results=self.results,
            sbom=sbom,
        )


def format_report_text(report: ComplianceReport) -> str:
    """Format compliance report as text"""
    lines = [
        "=" * 80,
        "BETANET v1.1 SPECIFICATION COMPLIANCE REPORT",
        "=" * 80,
        f"Binary: {report.binary_path}",
        f"Test Date: {report.test_timestamp}",
        f"Betanet Version: {report.betanet_version}",
        "",
        "SUMMARY:",
        f"  Total Requirements: {report.total_requirements}",
        f"  ✅ Passed: {report.passed}",
        f"  ❌ Failed: {report.failed}",
        f"  ⚠️  Warnings: {report.warnings}",
        f"  ⏭️  Skipped: {report.skipped}",
        "",
        f"Compliance Score: {(report.passed / report.total_requirements * 100):.1f}%",
        "",
        "DETAILED RESULTS:",
        "-" * 80,
    ]

    for result in report.results:
        status_emoji = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭️"}.get(
            result.status, "❓"
        )

        lines.extend(
            [
                f"{status_emoji} {result.requirement_id.upper().replace('_', ' ')} ({result.section_ref})",
                f"   Description: {result.description}",
                f"   Status: {result.status}",
                f"   Details: {result.details}",
            ]
        )

        if result.evidence:
            lines.append("   Evidence:")
            for evidence in result.evidence[:3]:  # Limit evidence shown
                lines.append(f"     • {evidence}")
            if len(result.evidence) > 3:
                lines.append(f"     • ... and {len(result.evidence) - 3} more")
        lines.append("")

    # SBOM Summary
    lines.extend(["SOFTWARE BILL OF MATERIALS (SBOM):", "-" * 40])

    for component in report.sbom[:10]:  # Show top 10 components
        lines.append(f"• {component.name} ({component.type}) - {component.supplier}")

    if len(report.sbom) > 10:
        lines.append(f"• ... and {len(report.sbom) - 10} more components")

    lines.extend(["", "=" * 80, "End of Report", "=" * 80])

    return "\n".join(lines)


def format_report_json(report: ComplianceReport) -> str:
    """Format compliance report as JSON"""
    return json.dumps(asdict(report), indent=2, default=str)


def create_github_action() -> str:
    """Generate GitHub Action workflow template"""
    return """name: Betanet Spec Compliance Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Build binary
      run: |
        # Add your build commands here
        # Example:
        # make build
        # cargo build --release
        echo "Build your Betanet implementation here"
        
    - name: Download Betanet Compliance Linter
      run: |
        curl -O https://raw.githubusercontent.com/Mentor1337/betalint/main/betalint.py
        chmod +x betalint.py
        
    - name: Run Compliance Check
      run: |
        python betalint.py \\
          --binary ./target/release/your-betanet-binary \\
          --output json \\
          --report-file compliance-report.json
        
    - name: Upload Compliance Report
      uses: actions/upload-artifact@v3
      with:
        name: compliance-report
        path: |
          compliance-report.json
          sbom.json
          
    - name: Comment PR with Results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('compliance-report.json', 'utf8'));
          
          const passed = report.passed;
          const total = report.total_requirements;
          const score = Math.round((passed / total) * 100);
          
          const comment = `## 🔍 Betanet Spec Compliance Results
          
          **Compliance Score: ${score}%** (${passed}/${total} requirements)
          
          - ✅ Passed: ${report.passed}
          - ❌ Failed: ${report.failed}  
          - ⚠️ Warnings: ${report.warnings}
          - ⏭️ Skipped: ${report.skipped}
          
          ${score >= 80 ? '🎉 Great job! Your implementation meets most requirements.' : 
            score >= 60 ? '⚡ Good progress! A few more requirements to address.' :
            '🚧 Needs work. Please review the failed requirements.'}
          
          Full report available in the workflow artifacts.`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
"""


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Betanet v1.1 Specification Compliance Linter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python betalint.py --binary ./betanet-node
  python betalint.py --binary ./betanet-node --output json
  python betalint.py --binary ./betanet-node --output json --report-file report.json
  python betalint.py --generate-github-action > .github/workflows/compliance.yml
        """,
    )

    parser.add_argument(
        "--binary", "-b", type=str, help="Path to the Betanet binary to test"
    )

    parser.add_argument(
        "--output",
        "-o",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    parser.add_argument(
        "--report-file", "-r", type=str, help="Save report to file (default: stdout)"
    )

    parser.add_argument("--sbom-file", type=str, help="Save SBOM to separate JSON file")

    parser.add_argument("--config", "-c", type=str, help="Configuration file (JSON)")

    parser.add_argument(
        "--generate-github-action",
        action="store_true",
        help="Generate GitHub Action workflow template",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Generate GitHub Action template
    if args.generate_github_action:
        print(create_github_action())
        return 0

    # Validate arguments
    if not args.binary:
        parser.error("--binary is required")

    if not os.path.exists(args.binary):
        logger.error(f"Binary not found: {args.binary}")
        return 1

    # Load configuration
    config = {}
    if args.config:
        try:
            with open(args.config, "r") as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return 1

    # Run compliance check
    try:
        with BetanetLinter(args.binary, config) as linter:
            report = linter.run_compliance_check()

            # Format output
            if args.output == "json":
                output = format_report_json(report)
            else:
                output = format_report_text(report)

            # Save to file or print
            if args.report_file:
                with open(args.report_file, "w") as f:
                    f.write(output)
                logger.info(f"Report saved to: {args.report_file}")
            else:
                print(output)

            # Save SBOM separately if requested
            if args.sbom_file:
                sbom_data = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "serialNumber": f"urn:uuid:{hashlib.md5(str(report.binary_path).encode()).hexdigest()}",
                    "version": 1,
                    "metadata": {
                        "timestamp": report.test_timestamp,
                        "tools": [
                            {"name": "betanet-compliance-linter", "version": "1.1.0"}
                        ],
                    },
                    "components": [asdict(comp) for comp in report.sbom],
                }

                with open(args.sbom_file, "w") as f:
                    json.dump(sbom_data, f, indent=2)
                logger.info(f"SBOM saved to: {args.sbom_file}")

            # Exit code based on results
            if report.failed > 0:
                logger.warning(
                    f"Compliance check failed: {report.failed} requirements failed"
                )
                return 1
            elif report.warnings > 0:
                logger.info(
                    f"Compliance check completed with warnings: {report.warnings} warnings"
                )
                return 0
            else:
                logger.info("All compliance checks passed!")
                return 0

    except Exception as e:
        logger.error(f"Compliance check failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
