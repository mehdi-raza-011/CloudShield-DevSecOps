import os
import json
import re
import subprocess
from datetime import datetime

class CloudShieldGateway:
    def __init__(self):
        self.compliance_violations = []
        self.hardened_iam_policies = {}
        
        # Kubernetes scanning patterns
        self.k8s_privileged = re.compile(r"privileged:\s*true", re.IGNORECASE)
        self.k8s_host_network = re.compile(r"hostNetwork:\s*true", re.IGNORECASE)
        
        # Container & Secrets scanning patterns
        self.secret_patterns = re.compile(r"(password|passwd|secret|key|token|api_key)\s*=\s*", re.IGNORECASE)
        self.root_user_pattern = re.compile(r"^USER\s+root", re.IGNORECASE)

    def get_git_metadata(self):
        """Extracts current git environment properties."""
        try:
            branch = subprocess.check_output(["git", "branch", "--show-current"], stderr=subprocess.DEVNULL).decode().strip()
            last_commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL).decode().strip()
            return f"Branch: `{branch}` | Last Commit Hash: `{last_commit}`"
        except:
            return "Git Environment: Development Active"

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
            
    # MODULE 2: KUBERNETES MANIFEST SCANNER
    def audit_kubernetes_manifest(self, yaml_path):
        print(f"[+] Launching Kubernetes Cluster Scan: {yaml_path}")
        if not os.path.exists(yaml_path):
            return

        with open(yaml_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                
                # Check 1: Prevent pods from running in privileged mode
                if self.k8s_privileged.search(clean_line):
                    self.register_violation("CRITICAL", "Kubernetes Security", yaml_path, line_num,
                        "Pod is configured with 'privileged: true'. This allows container escape attacks.")
                
                # Check 2: Prevent pods from binding to the host's network
                if self.k8s_host_network.search(clean_line):
                    self.register_violation("HIGH", "Kubernetes Networking", yaml_path, line_num,
                        "Pod is binding to hostNetwork. This bypasses network isolation.")

    # MODULE 3: CLOUD POSTURE & AUTOMATED IAM REMEDIATION
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

        # Audit Identity Management (IAM)
        for policy in config.get("iam_policies", []):
            policy_name = policy["policy_name"]
            is_vulnerable = False
            
            for stmt in policy.get("statements", []):
                if "*" in stmt.get("actions", []) and "*" in stmt.get("resources", []):
                    self.register_violation("CRITICAL", "Identity & Access Management", policy_name, "IAM Statement",
                        f"Dangerous administrative wildcard access granted on all cloud assets.")
                    is_vulnerable = True

            # AUTOMATED REMEDIATION ENGINE
            if is_vulnerable:
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

    # NEW FEATURE: TERMINAL DASHBOARD
    def print_summary_dashboard(self):
        """Prints a professional ASCII summary table to the terminal."""
        critical = sum(1 for v in self.compliance_violations if v['severity'] == 'CRITICAL')
        high = sum(1 for v in self.compliance_violations if v['severity'] == 'HIGH')
        
        print("\n" + "="*55)
        print(" 🛡️  CLOUDSHIELD DEVSECOPS SECURITY SUMMARY")
        print("="*55)
        print(f"  [CRITICAL RISKS] : {critical}")
        print(f"  [HIGH RISKS]     : {high}")
        print("-" * 55)
        if critical > 0 or high > 0:
            print("  STATUS: 🔴 PIPELINE REJECTED")
        else:
            print("  STATUS: 🟢 PIPELINE SECURE")
        print("="*55 + "\n")

    # MODULE 4: COMPLIANCE LEDGER GENERATION & GIT LOGIC
    def generate_gate_reports(self):
        self.print_summary_dashboard()
        
        report_path = "pipeline_compliance_report.md"
        git_info = self.get_git_metadata()
        gate_passed = len(self.compliance_violations) == 0
        
        with open(report_path, 'w') as f:
            f.write("# DevSecOps Pipeline Security Gate Report\n")
            f.write(f"**Scan Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Git Tracking Status:** {git_info}  \n")
            f.write(f"**Gate Status:** {'🟢 PASSED' if gate_passed else '🔴 REJECTED'}  \n\n")
            
            f.write("## Security Risk Findings Ledger\n")
            for v in self.compliance_violations:
                f.write(f"### [{v['severity']}] - {v['category']}\n")
                f.write(f"* **Target Asset:** `{v['resource']}` (Location: `{v['location']}`)\n")
                f.write(f"* **Violation Details:** {v['description']}\n\n")

        # Output the machine-readable JSON artifact
        json_report_path = "cloudshield_results.json"
        with open(json_report_path, 'w') as f:
            json.dump({
                "metadata": {"timestamp": datetime.now().isoformat(), "git_context": git_info},
                "total_violations": len(self.compliance_violations),
                "findings": self.compliance_violations
            }, f, indent=2)

        # Output remediated configurations
        if self.hardened_iam_policies:
            remediation_path = "remediated_iam_blueprints.json"
            with open(remediation_path, 'w') as f:
                json.dump(self.hardened_iam_policies, f, indent=2)
                
        # Git Commit Blocking Logic
        critical_count = sum(1 for v in self.compliance_violations if v['severity'] in ['HIGH', 'CRITICAL'])
        if critical_count > 0:
            print(f"[!] {critical_count} CRITICAL/HIGH violations found. Aborting commit sequence.")
            exit(1)
        else:
            print("[+] Environment clean. Commit authorized.")
            exit(0)

if __name__ == "__main__":
    gateway = CloudShieldGateway()
    gateway.audit_container_manifest("Dockerfile")
    gateway.audit_kubernetes_manifest("deployment.yaml")
    gateway.audit_cloud_infrastructure("cloud_deployment.json")
    gateway.generate_gate_reports()
