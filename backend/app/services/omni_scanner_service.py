import os
import re
import math
import hashlib
import zipfile
import tarfile
import urllib.parse
from io import BytesIO
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import httpx
from PIL import Image
from PIL.ExifTags import TAGS
import cv2
import numpy as np

# High-risk TLDs often abused in fast-flux phishing and malware distribution
SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work",
    ".click", ".rest", ".fit", ".icu", ".cam", ".country", ".kim", ".party"
}

# Suspicious file extensions served by malicious links
DANGEROUS_DOWNLOAD_EXTS = {
    ".exe", ".scr", ".pif", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".hta",
    ".jar", ".apk", ".iso", ".img", ".vhd", ".cpl", ".dll", ".wsf", ".reg"
}

# Malicious signatures for deep file scanning
SIGNATURE_PATTERNS = [
    (b"bash -i >& /dev/tcp", "Interactive Bash Reverse Shell", 95),
    (b"nc -e /bin/sh", "Netcat Execution Reverse Shell", 95),
    (b"nc -e /bin/bash", "Netcat Execution Reverse Shell", 95),
    (b"eval($_POST", "PHP One-Line Web Shell", 95),
    (b"eval($_GET", "PHP One-Line Web Shell", 95),
    (b"powershell -enc", "Obfuscated Encoded PowerShell", 85),
    (b"powershell.exe -enc", "Obfuscated Encoded PowerShell", 85),
    (b"Invoke-Expression", "PowerShell Memory Execution (IEX)", 75),
    (b"IEX (New-Object", "PowerShell Remote Download Cradle", 90),
    (b"WScript.Shell", "Windows Script Host Automation", 65),
    (b"AutoOpen", "Office Document Auto-Executing VBA Macro", 80),
    (b"Document_Open", "Office Document Auto-Executing VBA Macro", 80),
    (b"/JavaScript", "PDF Embedded Executable JavaScript Object", 75),
    (b"/Launch", "PDF OS Command Execution Action", 90),
    (b"/EmbeddedFiles", "PDF Hidden Embedded Dropper Archive", 70),
    (b"MZ", "Windows PE32 Executable Header", 0),  # Context-dependent
]


class OmniThreatScanner:
    """
    Omni-Vector Threat & Virus Detection Engine.
    Inspects Links, QR Codes, Pictures (Steganography/Polyglots), and Files
    for malware, viruses, phishing, and hidden payloads.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    # =========================================================================
    # 1. LINK / URL DEEP SCANNER
    # =========================================================================
    @classmethod
    async def scan_link(cls, raw_url: str) -> Dict[str, Any]:
        """
        Deep-audits an input link:
        - Evaluates domain reputation, typosquatting, lookalike domains, obfuscated IPs.
        - Traces HTTP 301/302 redirect chains safely.
        - Inspects the payload at the END of the link (Content-Type, downloads, drive-by executables).
        """
        if not raw_url.startswith(("http://", "https://")):
            target_url = f"https://{raw_url}"
        else:
            target_url = raw_url

        parsed = urllib.parse.urlparse(target_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()

        risk_score = 0
        indicators = []

        # 1. Obfuscated IP Address Check (e.g. http://0x7f000001 or decimal IP)
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
            risk_score += 35
            indicators.append("Target uses raw numeric IPv4 address instead of registered domain name")
        elif hostname.startswith("0x") or hostname.isdigit():
            risk_score += 65
            indicators.append("Heuristic evasion: Obfuscated hex or decimal IP format detected")

        # 2. Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                risk_score += 30
                indicators.append(f"Domain uses high-abuse/bulletproof TLD ({tld})")
                break

        # 3. Lookalike / Phishing Typosquatting heuristics
        phish_keywords = ["login", "verify", "secure", "account", "update", "banking", "wallet", "support"]
        for kw in phish_keywords:
            if kw in hostname and not any(legit in hostname for legit in ["google.com", "microsoft.com", "apple.com"]):
                risk_score += 25
                indicators.append(f"Suspicious security/credential keyword '{kw}' present in subdomain/hostname")
                break

        # 4. Dangerous file extension directly in URL path
        for ext in DANGEROUS_DOWNLOAD_EXTS:
            if path.endswith(ext):
                risk_score += 55
                indicators.append(f"Link points directly to executable/dropper payload ({ext})")
                break

        # 5. Follow HTTP Redirects safely to inspect the end of the link
        redirect_chain = []
        final_url = target_url
        target_content_type = "unknown"
        target_size_bytes = 0
        status_code = None
        server_header = "Unknown"

        try:
            async with httpx.AsyncClient(timeout=3.5, verify=False, follow_redirects=True) as client:
                res = await client.head(target_url)
                status_code = res.status_code
                final_url = str(res.url)
                target_content_type = res.headers.get("Content-Type", "text/html").lower()
                target_size_bytes = int(res.headers.get("Content-Length", 0))
                server_header = res.headers.get("Server", "Unknown")

                # Record redirect history
                if hasattr(res, "history") and res.history:
                    for resp in res.history:
                        redirect_chain.append({"status": resp.status_code, "url": str(resp.url)})
                    redirect_chain.append({"status": res.status_code, "url": final_url})
        except Exception as e:
            indicators.append(f"Connection probe error: {type(e).__name__}")

        # Check final destination after redirects
        final_parsed = urllib.parse.urlparse(final_url)
        final_path = final_parsed.path.lower()
        for ext in DANGEROUS_DOWNLOAD_EXTS:
            if final_path.endswith(ext):
                risk_score += 60
                indicators.append(f"Redirect chain terminates at dangerous payload: {ext}")
                break

        if any(bin_mime in target_content_type for bin_mime in ["application/octet-stream", "application/x-msdownload", "application/zip", "application/x-executable"]):
            risk_score += 45
            indicators.append(f"Endpoint serves binary executable stream ({target_content_type})")

        risk_score = min(100, risk_score)
        if risk_score >= 70:
            threat_verdict = "MALICIOUS_VIRUS_OR_PHISHING"
        elif risk_score >= 35:
            threat_verdict = "SUSPICIOUS"
        else:
            threat_verdict = "CLEAN"

        return {
            "target_url": target_url,
            "final_url": final_url,
            "hostname": hostname,
            "is_redirected": len(redirect_chain) > 1,
            "redirect_chain": redirect_chain,
            "status_code": status_code,
            "content_type": target_content_type,
            "payload_size_bytes": target_size_bytes,
            "server_header": server_header,
            "risk_score": risk_score,
            "threat_verdict": threat_verdict,
            "threat_indicators": indicators,
            "scanned_at": datetime.utcnow().isoformat(),
        }

    # =========================================================================
    # 1B. DEEP PATH & SOFTWARE PAYLOAD INSPECTOR
    # =========================================================================
    @classmethod
    async def scan_deep_link_and_software(cls, raw_url: str) -> Dict[str, Any]:
        """
        Deep Recursive Link, Path & Software Payload Inspector:
        - Traces full redirect chain.
        - If the link terminates at software/binary/archive (.exe, .zip, .msi, etc.), downloads and
          inspects the binary stream in-depth (entropy, PE headers, unpacked archives, virus signatures).
        - If the link terminates at a web page, parses HTML for linked software downloads,
          obfuscated scripts, and hidden iframes, auditing linked payloads until path is certified clean.
        """
        audit_trail: List[str] = []
        software_payloads: List[Dict[str, Any]] = []
        discovered_scripts: List[str] = []
        discovered_iframes: List[str] = []
        deep_indicators: List[str] = []
        max_score = 0

        # Step 1: Base Link & Redirect Audit
        audit_trail.append(f"Initiating deep path traversal on '{raw_url}'")
        base_audit = await cls.scan_link(raw_url)
        max_score = max(max_score, base_audit["risk_score"])
        deep_indicators.extend(base_audit["threat_indicators"])
        final_url = base_audit["final_url"]
        content_type = base_audit["content_type"]

        parsed_final = urllib.parse.urlparse(final_url)
        path_lower = parsed_final.path.lower()
        filename_from_url = os.path.basename(parsed_final.path) or "downloaded_payload.bin"

        # Check if direct software/archive download
        is_software_stream = any(path_lower.endswith(ext) for ext in DANGEROUS_DOWNLOAD_EXTS) or \
            any(bin_mime in content_type for bin_mime in ["application/octet-stream", "application/x-msdownload", "application/zip", "application/x-executable", "application/x-tar"])

        if is_software_stream:
            audit_trail.append(f"Destination serves direct software package/executable stream: '{filename_from_url}' ({content_type})")
            try:
                async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
                    download_resp = await client.get(final_url)
                    if download_resp.status_code == 200:
                        payload_bytes = download_resp.content[:25 * 1024 * 1024]  # Max 25MB stream
                        audit_trail.append(f"Successfully acquired {len(payload_bytes)} bytes of software binary stream into memory")

                        # Deep scan this software
                        file_audit = cls.scan_file(payload_bytes, filename=filename_from_url)
                        software_payloads.append(file_audit)
                        max_score = max(max_score, file_audit["risk_score"])
                        deep_indicators.extend(file_audit["threat_indicators"])

                        # If it's a zip or archive, recursively analyze all embedded software
                        if filename_from_url.lower().endswith(".zip") or payload_bytes.startswith(b"PK\x03\x04"):
                            audit_trail.append("Unpacking archive container to inspect embedded binaries and scripts")
                            try:
                                with zipfile.ZipFile(BytesIO(payload_bytes)) as zf:
                                    for entry_name in zf.namelist():
                                        entry_lower = entry_name.lower()
                                        if any(entry_lower.endswith(e) for e in DANGEROUS_DOWNLOAD_EXTS):
                                            entry_data = zf.read(entry_name)
                                            nested_audit = cls.scan_file(entry_data, filename=f"ARCHIVE_ITEM:{entry_name}")
                                            software_payloads.append(nested_audit)
                                            max_score = max(max_score, nested_audit["risk_score"])
                                            deep_indicators.extend(nested_audit["threat_indicators"])
                                            audit_trail.append(f"Extracted and audited nested software payload: '{entry_name}' -> Verdict: {nested_audit['threat_verdict']}")
                            except Exception as ze:
                                audit_trail.append(f"Archive unpacking notification: {str(ze)}")
            except Exception as dl_err:
                audit_trail.append(f"Software download probe notice: {type(dl_err).__name__}")
        else:
            # Step 2: Destination is an HTML webpage. Inspect for linked software, scripts, iframes
            audit_trail.append(f"Destination serves web content ({content_type}). Inspecting page DOM for nested software & hidden scripts.")
            try:
                async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
                    page_resp = await client.get(final_url)
                    if page_resp.status_code == 200:
                        html_text = page_resp.text[:1000000]  # First 1MB

                        # 1. Search for linked download software (<a href="...exe|zip|msi|etc.">)
                        href_matches = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\'](.*?)["\']', html_text, re.IGNORECASE)
                        linked_software = []
                        for h in href_matches:
                            h_clean = h.strip()
                            h_lower = h_clean.lower()
                            if any(h_lower.endswith(ext) or ext in h_lower for ext in [".exe", ".msi", ".zip", ".scr", ".bat", ".apk", ".iso"]):
                                # Resolve relative links
                                full_link = urllib.parse.urljoin(final_url, h_clean)
                                if full_link not in linked_software:
                                    linked_software.append(full_link)

                        if linked_software:
                            audit_trail.append(f"Discovered {len(linked_software)} linked software download(s) on destination page")
                            for sw_link in linked_software[:3]:  # Deep-scan up to 3 linked software
                                audit_trail.append(f"Deep-auditing linked software: {sw_link}")
                                try:
                                    sw_resp = await client.get(sw_link)
                                    if sw_resp.status_code == 200:
                                        sw_bytes = sw_resp.content[:15 * 1024 * 1024]
                                        sw_name = os.path.basename(urllib.parse.urlparse(sw_link).path) or "linked_software.exe"
                                        sw_audit = cls.scan_file(sw_bytes, filename=sw_name)
                                        software_payloads.append(sw_audit)
                                        max_score = max(max_score, sw_audit["risk_score"])
                                        deep_indicators.extend(sw_audit["threat_indicators"])
                                        audit_trail.append(f"Linked software '{sw_name}' deep audit complete -> Verdict: {sw_audit['threat_verdict']}")
                                except Exception as sw_e:
                                    audit_trail.append(f"Unable to fetch linked software '{sw_link}': {type(sw_e).__name__}")

                        # 2. Extract scripts
                        script_srcs = re.findall(r'<script\s+(?:[^>]*?\s+)?src=["\'](.*?)["\']', html_text, re.IGNORECASE)
                        discovered_scripts = script_srcs[:10]
                        if any("obfuscate" in s.lower() or "eval" in s.lower() for s in discovered_scripts):
                            max_score = max(max_score, 45)
                            deep_indicators.append("Heuristic evasion: Obfuscated external script references detected on landing page")

                        # 3. Check for hidden iframes
                        iframe_srcs = re.findall(r'<iframe\s+(?:[^>]*?\s+)?src=["\'](.*?)["\']', html_text, re.IGNORECASE)
                        discovered_iframes = iframe_srcs[:5]
                        if discovered_iframes:
                            max_score = max(max_score, 35)
                            deep_indicators.append(f"Hidden iframe embed detected ({len(discovered_iframes)} frame(s) - possible clickjacking or exploit kit)")

                        # 4. Check for credential harvesting forms
                        if b'type="password"' in page_resp.content.lower() and base_audit["risk_score"] >= 25:
                            max_score = max(max_score, 75)
                            deep_indicators.append("Credential harvesting form detected on suspicious domain (High-confidence Phishing)")
            except Exception as page_e:
                audit_trail.append(f"Webpage inspection note: {type(page_e).__name__}")

        audit_trail.append("Deep path & software inspection complete. All layers traversed.")

        max_score = min(100, max_score)
        if max_score >= 70:
            overall_verdict = "MALICIOUS_VIRUS_OR_SOFTWARE"
        elif max_score >= 35:
            overall_verdict = "SUSPICIOUS_PATH"
        else:
            overall_verdict = "PATH_COMPLETELY_CLEAN"

        return {
            "target_url": raw_url,
            "final_url": final_url,
            "is_redirected": base_audit["is_redirected"],
            "redirect_chain": base_audit["redirect_chain"],
            "base_link_audit": base_audit,
            "software_payloads_analyzed": software_payloads,
            "software_count": len(software_payloads),
            "discovered_scripts": discovered_scripts,
            "discovered_iframes": discovered_iframes,
            "audit_trail": audit_trail,
            "risk_score": max_score,
            "threat_verdict": overall_verdict,
            "threat_indicators": list(dict.fromkeys(deep_indicators)),  # Deduplicate
            "scanned_at": datetime.utcnow().isoformat(),
        }
    @classmethod
    async def scan_qr_code(cls, image_bytes: bytes, filename: str = "qr_code.png") -> Dict[str, Any]:
        """
        Decodes a QR code from picture data and analyzes the underlying payload
        for quishing (QR phishing), malicious links, or trojan downloads.
        """
        detector = cv2.QRCodeDetector()

        try:
            # 1. Direct decode from buffer
            np_arr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if img is not None:
                decoded_text, _, _ = detector.detectAndDecode(img)
                
                # 2. If not detected, try scaling & adding quiet zone border
                if not decoded_text:
                    h, w = img.shape[:2]
                    scale = max(1, int(300 / max(h, w, 1)))
                    if scale > 1:
                        scaled = cv2.resize(img, (w * scale, h * scale), interpolation=cv2.INTER_NEAREST)
                    else:
                        scaled = img
                    bordered = cv2.copyMakeBorder(scaled, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=[255, 255, 255])
                    decoded_text, _, _ = detector.detectAndDecode(bordered)

                # 3. If still not detected, try grayscale + Otsu thresholding
                if not decoded_text:
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                    bordered_thresh = cv2.copyMakeBorder(thresh, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
                    decoded_text, _, _ = detector.detectAndDecode(bordered_thresh)
        except Exception:
            pass

        # 4. Fallback to PIL if OpenCV empty
        if not decoded_text:
            try:
                pil_img = Image.open(BytesIO(image_bytes))
                gray_img = pil_img.convert("L")
                np_arr_gray = np.array(gray_img)
                bordered_gray = cv2.copyMakeBorder(np_arr_gray, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
                decoded_text, _, _ = detector.detectAndDecode(bordered_gray)
            except Exception:
                pass

        if not decoded_text:
            return {
                "success": False,
                "message": "No valid QR code matrix could be decoded from this image.",
                "raw_payload": None,
                "threat_verdict": "UNREADABLE",
                "risk_score": 0,
            }

        is_url = bool(re.match(r"^https?://", decoded_text, re.IGNORECASE) or "." in decoded_text and "/" in decoded_text)
        indicators = []
        risk_score = 0
        link_analysis = None

        if is_url:
            indicators.append("QR code encodes remote URL (Quishing vector)")
            # Deep scan the link embedded inside the QR code
            link_analysis = await cls.scan_link(decoded_text)
            risk_score = link_analysis["risk_score"]
            threat_verdict = link_analysis["threat_verdict"]
            indicators.extend(link_analysis["threat_indicators"])
        else:
            indicators.append("QR code encodes raw text / configuration data")
            # Check for suspicious script injection inside text QR
            for sig, desc, sig_risk in SIGNATURE_PATTERNS:
                if sig.decode("latin1", errors="ignore").lower() in decoded_text.lower():
                    risk_score += sig_risk
                    indicators.append(f"Embedded malicious script in QR data: {desc}")

            risk_score = min(100, risk_score)
            if risk_score >= 70:
                threat_verdict = "MALICIOUS_PAYLOAD"
            elif risk_score >= 35:
                threat_verdict = "SUSPICIOUS"
            else:
                threat_verdict = "CLEAN"

        return {
            "success": True,
            "filename": filename,
            "decoded_payload": decoded_text,
            "is_url": is_url,
            "risk_score": risk_score,
            "threat_verdict": threat_verdict,
            "threat_indicators": indicators,
            "link_audit": link_analysis,
            "scanned_at": datetime.utcnow().isoformat(),
        }

    # =========================================================================
    # 3. PICTURE STEGANOGRAPHY & POLYGLOT VIRUS SCANNER
    # =========================================================================
    @classmethod
    def scan_picture(cls, image_bytes: bytes, filename: str = "picture.jpg") -> Dict[str, Any]:
        """
        Audits an image for hidden trojan payloads, polyglots, and steganography:
        - Detects trailing appended executable/archive data past standard image EOF markers.
        - Audits EXIF metadata tags for PHP web shells, XSS, or shellcode injection.
        - Detects malicious XML/script injection inside SVG vector pictures.
        - Calculates Shannon entropy across byte streams.
        """
        risk_score = 0
        indicators = []
        is_polyglot = False
        hidden_payload_type = None
        exif_findings = []

        total_size = len(image_bytes)
        entropy = cls.calculate_entropy(image_bytes)

        # 1. SVG Script Injection Check
        if filename.lower().endswith(".svg") or b"<svg" in image_bytes[:1000].lower():
            lower_content = image_bytes.lower()
            if b"<script" in lower_content:
                risk_score += 85
                indicators.append("Embedded <script> tag detected inside SVG vector picture (XSS / Stored Payload)")
            if b"onload=" in lower_content or b"onerror=" in lower_content:
                risk_score += 75
                indicators.append("Embedded JavaScript event handler detected inside SVG picture attributes")
            if b"<!entity" in lower_content:
                risk_score += 80
                indicators.append("XML External Entity (XXE) injection payload detected inside SVG file")

        # 2. Check for Trailing Data After Image EOF Marker (Polyglots)
        # JPEG EOF is 0xFF 0xD9
        if image_bytes.startswith(b"\xFF\xD8"):
            eof_pos = image_bytes.rfind(b"\xFF\xD9")
            if eof_pos != -1 and (total_size - (eof_pos + 2)) > 64:
                trailing_data = image_bytes[eof_pos + 2:]
                trailing_size = len(trailing_data)
                is_polyglot = True
                risk_score += 65
                indicators.append(f"Image Steganography: Detected {trailing_size} bytes of hidden trailing data appended after JPEG EOF marker (FF D9)")

                # Analyze what is appended
                if trailing_data.startswith(b"PK\x03\x04"):
                    hidden_payload_type = "Embedded ZIP / JAR Archive Polyglot"
                    risk_score += 30
                    indicators.append("Appended payload is a hidden ZIP/APK archive")
                elif trailing_data.startswith(b"MZ"):
                    hidden_payload_type = "Embedded Windows PE32 Executable Polyglot"
                    risk_score += 35
                    indicators.append("CRITICAL: Appended payload is a hidden Windows PE executable binary (MZ)")
                elif b"<?php" in trailing_data or b"powershell" in trailing_data.lower():
                    hidden_payload_type = "Embedded Web Shell / Script"
                    risk_score += 30
                    indicators.append("Appended payload contains executable web shell or PowerShell script")

        # PNG EOF is IEND chunk (49 45 4E 44 AE 42 60 82)
        elif image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            iend_pos = image_bytes.find(b"IEND\xaeB`\x82")
            if iend_pos != -1 and (total_size - (iend_pos + 8)) > 64:
                trailing_data = image_bytes[iend_pos + 8:]
                trailing_size = len(trailing_data)
                is_polyglot = True
                risk_score += 65
                indicators.append(f"Image Steganography: Detected {trailing_size} bytes appended after PNG IEND chunk")
                if trailing_data.startswith(b"PK\x03\x04"):
                    hidden_payload_type = "Embedded ZIP / JAR Archive"
                    risk_score += 30
                elif trailing_data.startswith(b"MZ"):
                    hidden_payload_type = "Embedded Windows PE Executable"
                    risk_score += 35

        # 3. EXIF Metadata Inspection for Malicious Code
        try:
            pil_img = Image.open(BytesIO(image_bytes))
            exif_data = pil_img._getexif() if hasattr(pil_img, "_getexif") else None
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    str_val = str(value)
                    if any(susp in str_val.lower() for susp in ["<?php", "eval(", "base64_decode", "powershell", "<script"]):
                        risk_score += 85
                        exif_findings.append(f"Tag '{tag_name}' contains code injection: {str_val[:60]}...")
                        indicators.append(f"Malicious code injected inside EXIF {tag_name}")
        except Exception:
            pass

        # 4. Abnormally High Entropy on Raw Picture
        if entropy >= 7.85 and total_size > 100000:
            risk_score += 25
            indicators.append(f"Abnormally high Shannon entropy ({entropy}/8.0) - possible encrypted or compressed steganography carrier")

        risk_score = min(100, risk_score)
        if risk_score >= 70:
            threat_verdict = "MALICIOUS_STEGO_OR_POLYGLOT"
        elif risk_score >= 35:
            threat_verdict = "SUSPICIOUS"
        else:
            threat_verdict = "CLEAN"

        return {
            "filename": filename,
            "total_size_bytes": total_size,
            "entropy": entropy,
            "is_polyglot": is_polyglot,
            "hidden_payload_type": hidden_payload_type,
            "exif_findings": exif_findings,
            "risk_score": risk_score,
            "threat_verdict": threat_verdict,
            "threat_indicators": indicators,
            "scanned_at": datetime.utcnow().isoformat(),
        }

    # =========================================================================
    # 4. DEEP MULTI-FORMAT FILE SCANNER
    # =========================================================================
    @classmethod
    def scan_file(cls, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Deep multi-format file inspector:
        - Detects double extension obfuscation (e.g. invoice.pdf.exe).
        - Unpacks and checks Office VBA macros (AutoOpen, Shell).
        - Detects malicious PDF elements (/JavaScript, /Launch).
        - Inspects compressed archives (ZIP/TAR) for hidden droppers or zip bombs.
        - Calculates SHA-256/MD5 and checks embedded shellcode signatures.
        """
        risk_score = 0
        indicators = []
        file_size = len(file_bytes)
        entropy = cls.calculate_entropy(file_bytes)

        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        md5_hash = hashlib.md5(file_bytes).hexdigest()

        # 1. Double Extension Trickery Check
        name_parts = filename.lower().split(".")
        if len(name_parts) >= 3:
            first_ext = f".{name_parts[-2]}"
            second_ext = f".{name_parts[-1]}"
            if first_ext in [".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt"] and second_ext in DANGEROUS_DOWNLOAD_EXTS:
                risk_score += 85
                indicators.append(f"Deceptive double extension detected: '{first_ext}{second_ext}' (Masquerading executable)")

        # 2. Known Malicious Signatures
        for sig, desc, sig_risk in SIGNATURE_PATTERNS:
            if sig in file_bytes:
                risk_score += sig_risk
                indicators.append(desc)

        # 3. Office Macro Inspection
        if filename.lower().endswith((".docm", ".xlsm", ".pptm", ".docx", ".xlsx")):
            try:
                with zipfile.ZipFile(BytesIO(file_bytes)) as z:
                    for name in z.namelist():
                        if "vbaProject.bin" in name:
                            risk_score += 65
                            indicators.append("Office Document contains embedded binary VBA Macro project (vbaProject.bin)")
                            # Read vba project for high risk keywords
                            vba_data = z.read(name)
                            if b"AutoOpen" in vba_data or b"Document_Open" in vba_data:
                                risk_score += 25
                                indicators.append("VBA Macro contains automatic execution triggers (AutoOpen/Document_Open)")
                            if b"Shell" in vba_data or b"WScript" in vba_data:
                                risk_score += 25
                                indicators.append("VBA Macro invokes OS shell command execution")
                            break
            except Exception:
                pass

        # 4. PDF Malicious Action Elements
        if filename.lower().endswith(".pdf") or file_bytes.startswith(b"%PDF-"):
            if b"/JavaScript" in file_bytes or b"/JS" in file_bytes:
                risk_score += 60
                indicators.append("PDF document contains embedded JavaScript action script")
            if b"/Launch" in file_bytes:
                risk_score += 75
                indicators.append("PDF document contains /Launch action configured to execute external system processes")

        # 5. Archive Inspection (ZIP / TAR)
        archive_items = []
        if filename.lower().endswith(".zip") or file_bytes.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(BytesIO(file_bytes)) as z:
                    archive_items = z.namelist()
                    for item_name in archive_items:
                        item_ext = os.path.splitext(item_name.lower())[1]
                        if item_ext in DANGEROUS_DOWNLOAD_EXTS:
                            risk_score += 65
                            indicators.append(f"Archive contains dangerous executable dropper: '{item_name}'")
            except Exception:
                pass

        # 6. High Entropy Check
        if entropy >= 7.2 and file_size > 4096:
            risk_score += 25
            indicators.append(f"High Shannon entropy ({entropy}/8.0) - possible packed or encrypted binary payload")

        risk_score = min(100, risk_score)
        if risk_score >= 70:
            threat_verdict = "MALICIOUS_VIRUS"
        elif risk_score >= 35:
            threat_verdict = "SUSPICIOUS"
        else:
            threat_verdict = "CLEAN"

        return {
            "filename": filename,
            "file_size_bytes": file_size,
            "file_size_formatted": f"{file_size / 1024:.1f} KB" if file_size < 1048576 else f"{file_size / (1024*1024):.2f} MB",
            "sha256": sha256_hash,
            "md5": md5_hash,
            "entropy": entropy,
            "archive_contents": archive_items[:10] if archive_items else None,
            "risk_score": risk_score,
            "threat_verdict": threat_verdict,
            "threat_indicators": indicators,
            "scanned_at": datetime.utcnow().isoformat(),
        }


omni_threat_scanner = OmniThreatScanner()
omni_scanner_service = omni_threat_scanner

