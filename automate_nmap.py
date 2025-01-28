from flask import Flask, render_template, request
import nmap
import datetime
import json

app = Flask(__name__)

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sS -Pn -T4")
    scan_result = {}
    for host in nm.all_hosts():
        scan_result[host] = {
            "hostname": nm[host].hostname(),
            "status": nm[host].state(),
            "open_ports": []
        }

        for protocol in nm[host].all_protocols():
            ports = nm[host][protocol].keys()
            for port in ports:
                port_info = {
                    "port": port,
                    "service": nm[host][protocol][port]["name"],
                    "state": nm[host][protocol][port]["state"]
                }
                scan_result[host]["open_ports"].append(port_info)
    
    return scan_result

@app.route("/", methods=["GET", "POST"])
def index():
    scan_results = None
    if request.method == "POST":
        target = request.form.get("target")
        scan_results = nmap_scan(target)
        # Save the report as a JSON file
        report = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_data": scan_results
        }
        with open("nmap_scan_report.json", "w") as f:
            json.dump(report, f, indent=4)
    
    return render_template("nmap.html", scan_results=scan_results)

if __name__ == "__main__":
    app.run(debug=True)
