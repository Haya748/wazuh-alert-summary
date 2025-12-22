#!/usr/bin/env python3
import json
import subprocess
from datetime import datetime

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
DATE_NOW = datetime.now().strftime("%Y-%m-%d")
ADMIN_EMAIL = "[my account]"
def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)
# =======================
# Read Agents
# =======================
agents_output = run("/var/ossec/bin/agent_control -l")
agents = []
for line in agents_output.splitlines():
    line = line.strip()
    if not line or line.startswith("Wazuh") or line.startswith("List"):
        continue
    try:
        if 'ID: ' in line:
            id_start = line.find('ID: ') + 4
            agent_id = line[id_start:id_start + 3]
        else:
            continue
        name_start = line.find('Name: ') + 6
        name_end = line.find(',', name_start)
        agent_name = line[name_start:name_end].strip()
        status = line.split(',')[-1].strip()
        if agent_id == "000" or "(server)" in agent_name:
            continue
        agents.append({
            "id": agent_id,
            "name": agent_name,
            "status": status
        })
    except:
        continue
# =======================
# Load alerts.json
# =======================
alerts = []
try:
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
except FileNotFoundError:
    pass
# =======================
# Build Report
# =======================
report = []
report.append("Dear Admin,\n")
report.append(f"Here is the weekly security summary ({DATE_NOW}):\n")
total_all_logs = 0
agent_alert_counts = {}
for agent in agents:
    agent_id = agent["id"]
    agent_name = agent["name"]
    agent_status = agent["status"]
    agent_alerts = [a for a in alerts if a.get("agent", {}).get("id") == agent_id]
    total = len(agent_alerts)
    total_all_logs += total
    agent_alert_counts[agent_name] = total

    critical = len([a for a in agent_alerts if a.get("rule", {}).get("level", 0) >= 8])
    high = len([a for a in agent_alerts if a.get("rule", {}).get("level") == 7])
    medium = len([a for a in agent_alerts if 4 <= a.get("rule", {}).get("level", 0) <= 6])
    low = len([a for a in agent_alerts if 1 <= a.get("rule", {}).get("level", 0) <= 3])
    attacks = {}
    for a in agent_alerts:
        desc = a.get("rule", {}).get("description", "Unknown")
        attacks[desc] = attacks.get(desc, 0) + 1
    common_attack = max(attacks, key=attacks.get) if attacks else "No attacks detected"
    report.append(f"\n<<< {agent_name} >>>")
    report.append(f"Agent Status: {agent_status}")
    report.append(f"Critical alert(s): {critical}")
    report.append(f"High alert(s): {high}")
    report.append(f"Medium alert(s): {medium}")
    report.append(f"Low alert(s): {low}")
    report.append(f"Total logs in this Agent is: {total}")
    report.append("\nDetected attack(s):")
    for attack, count in attacks.items():
        report.append(f"   - {attack} ({count} logs)")
    report.append(f"\nMost common attack for this Agent is: {common_attack}\n")
top_agent = max(agent_alert_counts, key=agent_alert_counts.get) if agent_alert_counts else "None"
report.append(f"Total logs for all Agents: {total_all_logs}")
report.append(f"Most alerts come from Agent: {top_agent}")
manager_status = run("systemctl is-active wazuh-manager").strip()
report.append(f"Manager Status: {manager_status}\n")
report.append("Best Regards,\nSIEMonster\n")
full_report = "\n".join(report)
send_cmd = f'echo "{full_report}" | mail -s "Weekly Wazuh Security Summary - {DATE_NOW}" {ADMIN_EMAIL}'
subprocess.call(send_cmd, shell=True)
