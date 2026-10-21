import json
from datetime import datetime
from typing import Dict, Any, List, Optional


class NetworkAnalysisService:
    """
    Network Telemetry & Zeek Event Analysis Service.
    Parses connection and DNS metadata, correlates network observations with host incidents,
    and detects outbound port/volume anomalies.
    """

    SUSPICIOUS_OUTBOUND_PORTS = {
        1337: "Common Hacker/C2 Backdoor Port",
        4444: "Metasploit Default Listener",
        5555: "Android Debug Bridge / Backdoor",
        6667: "IRC Botnet C2",
        8088: "Suspicious HTTP Proxy",
        8888: "Suspicious High Web Service",
        9001: "Tor Onion Router / C2",
        31337: "Elite Backdoor Trojan",
    }

    WELL_KNOWN_BENIGN_SERVICES = {
        80: "http",
        443: "https",
        53: "dns",
        22: "ssh",
        123: "ntp",
    }

    def parse_zeek_conn_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single Zeek conn.log JSON or TSV line into a structured observation.
        """
        clean = line.strip()
        if not clean or clean.startswith("#"):
            return None

        # Check if JSON formatted
        if clean.startswith("{") and clean.endswith("}"):
            try:
                data = json.loads(clean)
                return {
                    "source_type": "ZEEK_CONN",
                    "protocol": data.get("proto", "TCP").upper(),
                    "src_ip": data.get("id.orig_h") or data.get("src_ip", "0.0.0.0"),
                    "src_port": int(data.get("id.orig_p") or data.get("src_port", 0)),
                    "dst_ip": data.get("id.resp_h") or data.get("dst_ip", "0.0.0.0"),
                    "dst_port": int(data.get("id.resp_p") or data.get("dst_port", 0)),
                    "service": data.get("service"),
                    "duration_seconds": float(data.get("duration", 0.0) or 0.0),
                    "bytes_orig": int(data.get("orig_bytes", 0) or 0),
                    "bytes_resp": int(data.get("resp_bytes", 0) or 0),
                    "is_outbound": True,
                }
            except Exception:
                return None

        # Fallback to TSV split
        parts = clean.split("\t")
        if len(parts) >= 7:
            try:
                return {
                    "source_type": "ZEEK_CONN",
                    "protocol": parts[6].upper(),
                    "src_ip": parts[2],
                    "src_port": int(parts[3]),
                    "dst_ip": parts[4],
                    "dst_port": int(parts[5]),
                    "service": parts[7] if len(parts) > 7 and parts[7] != "-" else None,
                    "duration_seconds": float(parts[8]) if len(parts) > 8 and parts[8] != "-" else 0.0,
                    "bytes_orig": int(parts[9]) if len(parts) > 9 and parts[9] != "-" else 0,
                    "bytes_resp": int(parts[10]) if len(parts) > 10 and parts[10] != "-" else 0,
                    "is_outbound": True,
                }
            except Exception:
                return None

        return None

    def evaluate_network_anomaly(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates baseline anomaly score (0.0 to 1.0) and anomaly rationale.
        """
        dst_port = observation.get("dst_port", 0)
        is_outbound = observation.get("is_outbound", True)
        anomaly_score = 0.0
        reasons = []

        if is_outbound:
            if dst_port in self.SUSPICIOUS_OUTBOUND_PORTS:
                anomaly_score += 0.85
                reasons.append(f"Connection targeting known backdoor/C2 port {dst_port} ({self.SUSPICIOUS_OUTBOUND_PORTS[dst_port]}).")
            elif dst_port not in self.WELL_KNOWN_BENIGN_SERVICES and dst_port < 1024:
                anomaly_score += 0.40
                reasons.append(f"Outbound connection targeting non-standard low system port {dst_port}.")
            elif dst_port > 49152:
                # Ephemeral port target
                anomaly_score += 0.20

            # High byte ratio without HTTP/SSL service
            bytes_sent = observation.get("bytes_orig", 0)
            if bytes_sent > 10_000_000 and not observation.get("service"):
                anomaly_score += 0.35
                reasons.append(f"Large outbound data exfiltration volume observed ({bytes_sent} bytes) over unclassified service.")

        anomaly_score = min(1.0, round(anomaly_score, 2))
        is_anomalous = anomaly_score >= 0.50

        return {
            "is_anomalous": is_anomalous,
            "anomaly_score": anomaly_score,
            "anomaly_reason": "; ".join(reasons) if reasons else "Traffic consistent with baseline benign profile.",
        }


network_service = NetworkAnalysisService()
