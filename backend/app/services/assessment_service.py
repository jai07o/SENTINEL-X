import re
import ipaddress
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple
import httpx


class AssessmentService:
    """
    Authorized Penetration Testing & Vulnerability Assessment Service.
    Enforces non-bypassable scope authorization gates and performs safe, non-destructive checks.
    """

    PRIVATE_IP_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    REQUIRED_SECURITY_HEADERS = [
        {
            "header": "Strict-Transport-Security",
            "name": "HTTP Strict Transport Security (HSTS)",
            "owasp_category": "WSTG-CONF-07",
            "severity": "HIGH",
            "cvss": 7.5,
            "remediation": "Configure HSTS with 'max-age=31536000; includeSubDomains; preload' to enforce secure HTTPS transport.",
        },
        {
            "header": "Content-Security-Policy",
            "name": "Content Security Policy (CSP)",
            "owasp_category": "WSTG-CONF-12",
            "severity": "HIGH",
            "cvss": 7.2,
            "remediation": "Deploy a strict Content-Security-Policy header restricting script-src, style-src, and object-src to authorized origins.",
        },
        {
            "header": "X-Frame-Options",
            "name": "Anti-Clickjacking Frame Protection",
            "owasp_category": "WSTG-CLNT-09",
            "severity": "MEDIUM",
            "cvss": 5.4,
            "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent malicious iframe framing and UI redressing attacks.",
        },
        {
            "header": "X-Content-Type-Options",
            "name": "MIME-Type Sniffing Protection",
            "owasp_category": "WSTG-CONF-12",
            "severity": "LOW",
            "cvss": 3.7,
            "remediation": "Add 'X-Content-Type-Options: nosniff' to instruct browsers to follow declared MIME types strictly.",
        },
        {
            "header": "Referrer-Policy",
            "name": "Referrer Leakage Policy",
            "owasp_category": "WSTG-CONF-12",
            "severity": "LOW",
            "cvss": 3.1,
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to avoid exposing query parameters or path data.",
        },
    ]

    @staticmethod
    def is_private_ip(host_or_ip: str) -> bool:
        """Determines if target resolves to private or loopback IP range."""
        try:
            ip_obj = ipaddress.ip_address(host_or_ip)
            return any(ip_obj in net for net in AssessmentService.PRIVATE_IP_NETWORKS)
        except ValueError:
            # Domain name; resolve and check
            try:
                resolved_ips = socket.getaddrinfo(host_or_ip, None)
                for item in resolved_ips:
                    ip_str = item[4][0]
                    ip_obj = ipaddress.ip_address(ip_str)
                    if any(ip_obj in net for net in AssessmentService.PRIVATE_IP_NETWORKS):
                        return True
            except Exception:
                pass
        return False

    def validate_target_scope(
        self,
        target: str,
        authorized_scopes: List[Any],
        method: str = "HTTP_HEADERS",
        allow_private_lab: bool = True,
    ) -> Tuple[bool, Optional[str]]:
        """
        MANDATORY SCOPE GATE.
        Blocks unauthorized destinations, expired scopes, and private IPs unless explicitly authorized.
        """
        cleaned_target = target.strip()
        parsed = urlparse(cleaned_target)
        hostname = parsed.hostname or cleaned_target
        now = datetime.utcnow()

        # Check against private network SSRF protections
        if not allow_private_lab and self.is_private_ip(hostname):
            return False, "Target resolves to private/loopback address and private lab mode is not authorized."

        # Verify against active authorization scopes in project
        matched_scope = None
        for scope in authorized_scopes:
            if not getattr(scope, "is_active", True):
                continue

            # Expiration check
            if scope.expires_at and scope.expires_at < now:
                continue

            # Scope pattern match (exact match or wildcard domain)
            scope_target = scope.target.strip()
            if scope_target.startswith("*."):
                domain_suffix = scope_target[2:]
                if hostname.endswith(domain_suffix) or hostname == domain_suffix:
                    matched_scope = scope
                    break
            elif scope_target.lower() == hostname.lower() or scope_target.lower() == cleaned_target.lower():
                matched_scope = scope
                break

        if not matched_scope:
            return False, f"Target '{hostname}' is not authorized in current active project scopes or authorization has expired."

        # Check allowed methods
        allowed = getattr(matched_scope, "allowed_methods", "")
        if method and method not in allowed:
            return False, f"Requested assessment method '{method}' is not permitted by scope authorization contract."

        return True, None

    async def scan_http_security_headers(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Safe assessment: Analyzes HTTP response security headers against OWASP WSTG benchmarks.
        """
        findings = []
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                response = await client.get(target_url)
                headers = response.headers

                for check in self.REQUIRED_SECURITY_HEADERS:
                    h_key = check["header"].lower()
                    if h_key not in [k.lower() for k in headers.keys()]:
                        findings.append({
                            "title": f"Missing Security Header: {check['name']}",
                            "target": target_url,
                            "severity": check["severity"],
                            "cvss_score": check["cvss"],
                            "confidence": 0.95,
                            "owasp_category": check["owasp_category"],
                            "description": f"The target HTTP response does not include the recommended '{check['header']}' security header.",
                            "evidence_data": f"Status: {response.status_code}\nObserved Headers: {list(headers.keys())[:10]}",
                            "remediation": check["remediation"],
                        })

                # Server banner disclosure check
                server_header = headers.get("server") or headers.get("x-powered-by")
                if server_header:
                    findings.append({
                        "title": f"Server Software Information Disclosure: {server_header}",
                        "target": target_url,
                        "severity": "LOW",
                        "cvss_score": 3.5,
                        "confidence": 0.90,
                        "owasp_category": "WSTG-INFO-02",
                        "description": f"The server explicitly advertises software components via banner headers: '{server_header}'.",
                        "evidence_data": f"Server: {server_header}",
                        "remediation": "Suppress detailed version banners in web server configuration (e.g. ServerTokens Prod, expose_php = Off).",
                    })

        except Exception as e:
            findings.append({
                "title": f"HTTP Assessment Connection Error on {target_url}",
                "target": target_url,
                "severity": "INFO",
                "cvss_score": 0.0,
                "confidence": 1.0,
                "owasp_category": "WSTG-INFO-01",
                "description": f"Could not complete HTTP security assessment: {str(e)}",
                "evidence_data": str(e),
                "remediation": "Verify network reachability and firewall rules.",
            })

        return findings

    def check_tls_configuration(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Safe assessment: Inspects TLS certificate validity and SSL/TLS cipher protocol support.
        """
        result = {
            "hostname": hostname,
            "port": port,
            "tls_enabled": False,
            "certificate_valid": False,
            "issuer": None,
            "expires": None,
            "cipher_suite": None,
            "findings": [],
        }
        
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    result["tls_enabled"] = True
                    result["certificate_valid"] = True
                    result["cipher_suite"] = f"{cipher[0]} ({cipher[1]})" if cipher else "Unknown"
                    result["expires"] = cert.get("notAfter")
                    result["issuer"] = str(cert.get("issuer"))
        except ssl.SSLCertVerificationError as e:
            result["tls_enabled"] = True
            result["certificate_valid"] = False
            result["findings"].append({
                "title": f"Invalid or Self-Signed SSL/TLS Certificate on {hostname}",
                "target": f"{hostname}:{port}",
                "severity": "HIGH",
                "cvss_score": 7.4,
                "confidence": 0.98,
                "owasp_category": "WSTG-CRYP-01",
                "description": f"TLS certificate validation failed: {str(e)}",
                "evidence_data": str(e),
                "remediation": "Replace self-signed or untrusted certificates with a valid certificate from a recognized Certificate Authority (CA).",
            })
        except Exception as e:
            result["findings"].append({
                "title": f"TLS Connection Handshake Failed on {hostname}:{port}",
                "target": f"{hostname}:{port}",
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "confidence": 0.90,
                "owasp_category": "WSTG-CRYP-01",
                "description": f"Unable to establish TLS handshake: {str(e)}",
                "evidence_data": str(e),
                "remediation": "Ensure TLS is properly bound and port 443 is open.",
            })

        return result


assessment_service = AssessmentService()
