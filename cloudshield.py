import os
import json
import re
from datetime import datetime

class CloudShieldGateway:
    def __init__(self):
        self.compliance_violations = []
        self.hardened_iam_policies = {}
        
        # Compiled scanning patterns for deep container inspection
        self.secret_patterns = re.compile(r"(password|passwd|secret|key|token|api_key)\s*=\s*", re.IGNORECASE)
        self.root_user_pattern = re.compile(r"^USER\s+root", re.IGNORECASE)

    # MODULE 1: DEVSECOPS CONTAINER HARDENING SCANNER
    def audit_container_manifest(self, dockerfile_path):
        print(f"[+] Launching DevSecOps Container Scan: {dockerfile_path}")
        if not os.path.exists(dockerfile_path):
            return

        has_user_instruction = False
        with open(dockerfile_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                
                # Check for hardcoded credentials/tokens inside variables
                if self.secret_patterns.search(clean_line) and "ENV" in clean_line:
                    self.register_violation("CRITICAL", "Container Security", dockerfile_path, line_num,
                        f"Potential hardcoded credential leak detected: '{clean_line}'")
                
                # Monitor for insecure root execution patterns
                if self.root_user_pattern.search(clean_line):
                    self.register_violation("HIGH", "OS Hardening", dockerfile_path, line_num,
                        "Container explicitly configured to execute processes with root privileges.")
                    
                if clean_line.startswith("USER"):
                    has_user_instruction = True

        if not has_user_instruction:
            self.register_violation("HIGH", "Container Hardening", dockerfile_path, "EOF",
                "Missing explicit non-root USER instruction. Container will default to root execution.")

    # MODULE 2: CLOUD POSTURE & AUTOMATED IAM REMEDIATION
    def audit_cloud_infrastructure(self, cloud_json_path):
        print(f"[+] Launching Infrastructure-as-Code (IaC) Scan: {cloud_json_path}")
        if not os.path.exists(cloud_json_path):
            return

        with open(cloud_json_path, 'r') as f:
            config = json.load(f)

        # Audit Firewalls & Network Security Groups
        for sg in config.get("security_groups", []):
            for rule in sg.get("ingress_rules", []):
                if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") in [22, 3389, 23]:
                    self.register_violation("HIGH", "Network Security", sg["group_name"], f"Port {rule['port']}",
                        f"Management port {rule['port']} is globally exposed to the public internet.")

        # Audit Identity Management (IAM) & Apply Automated Least-Privilege Remediation
        for policy in config.get("iam_policies", []):
            policy_name = policy["policy_name"]
            statements = policy["statements"]
            is_vulnerable = False
            
            for stmt in statements:
                if "*" in stmt.get("actions", []) and "*" in stmt.get("resources", []):
                    self.register_violation("CRITICAL", "Identity & Access Management", policy_name, "IAM Statement",
                        f"Dangerous administrative wildcard access granted on all cloud assets.")
                    is_vulnerable = True

            # AUTOMATED REMEDIATION ENGINE: Rewrite over-permissive policies automatically
            if is_vulnerable:
                print(f" [!] Initiating Automated Remediation Engine for policy: {policy_name}")
                self.hardened_iam_policies[policy_name] = {
                    "remediation_status": "HARDENED_TO_LEAST_PRIVILEGE",
                    "original_policy": policy_name,
                    "enforced_statements": [
                        {
                            "effect": "Allow",
                            "actions": ["cloudwatch:ListMetrics", "cloudwatch:GetMetricData"],
                            "resources": ["arn:aws:cloudwatch:::log-stream/production-restricted"]
                        }
                    ]
                }

    def register_violation(self, severity, category, resource, location, desc):
        violation = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "resource": resource,
            "location": str(location),
            "description": desc
        }
        self.compliance_violations.append(violation)
        print(f"  [-] RISK DETECTED [{severity}] inside {category} ({resource} @ Line/Asset {location})")

    # MODULE 3: COMPLIANCE LEDGER GENERATION
    def generate_gate_reports(self):
        # 1. Output the compiled security findings
        report_path = "pipeline_compliance_report.md"
        with open(report_path, 'w') as f:
            f.write("# DevSecOps Pipeline Security Gate Report\n")
            f.write(f"**Scan Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Gate Status:** {'REJECTED' if self.compliance_violations else 'PASSED'}  \n\n")
            
            f.write("## Security Risk Findings Ledger\n")
            for v in self.compliance_violations:
                f.write(f"### [{v['severity']}] - {v['category']}\n")
                f.write(f"* **Target Asset:** `{v['resource']}` (Location: `{v['location']}`)\n")
                f.write(f"* **Violation Details:** {v['description']}\n\n")

        # 2. Output the automatically remediated configurations
        if self.hardened_iam_policies:
            remediation_path = "remediated_iam_blueprints.json"
            with open(remediation_path, 'w') as f:
                json.dump(self.hardened_iam_policies, f, indent=2)
            print(f"\n[+] Remediation complete. Hardened structures written to: {remediation_path}")
            
        print(f"[+] Security gate completed. Full report compiled in: {report_path}")

if __name__ == "__main__":
    gateway = CloudShieldGateway()
    gateway.audit_container_manifest("Dockerfile")
    gateway.audit_cloud_infrastructure("cloud_deployment.json")
    gateway.generate_gate_reports()