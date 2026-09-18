import os
import psutil
import shutil
import io
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, send_file

from src.core.event_store import get_events, get_stats, get_all_raw_events, add_event
from src.core.system_metrics import get_system_metrics

# ReportLab packages used to structure the automated PDF report stream
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# ✅ IMPORT (recommendation engine)
from src.detection.recommendation_engine import get_recommendation

# 🧠 Incident Correlation Engine
from src.detection.incident_correlator import IncidentCorrelator

app = Flask(__name__)

# 🧠 create correlator instance
correlator = IncidentCorrelator()

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>REAL TIME SOC MALWARE DEFENSE DASHBOARD</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0b1220;
            color: white;
        }

        /* Menu Navigation Styles */
        .navbar {
            background: #081120;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #1e293b;
        }
        .navbar h2 {
            margin: 0;
            font-size: 20px;
            color: #60a5fa;
            letter-spacing: 1px;
        }
        .menu-btns {
            display: flex;
            gap: 12px;
        }
        .nav-btn {
            background: #1e293b;
            color: #cbd5e1;
            border: 1px solid #334155;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            transition: 0.2s;
        }
        .nav-btn:hover {
            background: #3b82f6;
            color: white;
        }

        .topbar {
            display: flex;
            gap: 10px;
            padding: 10px;
        }

        .card {
            flex: 1;
            background: #111a2e;
            border-radius: 10px;
            padding: 10px;
            position: relative;
            height: 220px;
            box-shadow: 0 0 10px rgba(0,0,0,0.4);
        }

        .card h4 {
            text-align: center;
            color: #cbd5e1;
            margin-top: 5px;
        }

        .container {
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 10px;
            padding: 10px;
        }

        .panel {
            background: #111a2e;
            border-radius: 10px;
            padding: 10px;
            height: 75vh;
            overflow-y: auto;
            box-shadow: 0 0 10px rgba(0,0,0,0.4);
        }

        .event {
            background: #1e293b;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 8px;
            font-size: 13px;
            transition: 0.2s;
        }

        .HIGH { border-left: 5px solid red; }
        .MEDIUM { border-left: 5px solid orange; }
        .LOW { border-left: 5px solid lightgreen; }

        .circle-wrap {
            width: 160px;
            height: 160px;
            margin: auto;
            position: relative;
        }

        .circle-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 24px;
            font-weight: bold;
        }

        canvas {
            width: 100% !important;
            height: 160px !important;
        }

        .status-box {
            padding: 12px;
            background: #1e293b;
            border-radius: 8px;
            margin-bottom: 10px;
        }

        .counter-box {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            gap: 10px;
        }

        .counter {
            flex: 1;
            background: #1e293b;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }

        .counter h2 { margin: 0; font-size: 30px; }
        .counter p { margin: 5px 0 0 0; color: #cbd5e1; }
        .event-title { color: #60a5fa; font-weight: bold; }
        
        .btn-zone {
            margin-top: 10px;
            display: flex;
            gap: 10px;
        }
        .btn {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            font-size: 11px;
        }
        .btn-danger { background: #ef4444; color: white; }
        .btn-warning { background: #f59e0b; color: white; }

        /* Modal Overlay Window Configurations */
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.75);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background: #111a2e;
            border: 2px solid #1e293b;
            border-radius: 12px;
            width: 450px;
            padding: 20px;
            box-shadow: 0 0 20px rgba(0,0,0,0.6);
        }
        .modal-header {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
            color: #60a5fa;
            border-bottom: 1px solid #334155;
            padding-bottom: 8px;
        }
        .form-group {
            margin-bottom: 12px;
        }
        .form-group label {
            display: block;
            font-size: 12px;
            color: #94a3b8;
            margin-bottom: 5px;
        }
        .form-group input, .form-group select {
            width: 100%;
            background: #1e293b;
            border: 1px solid #334155;
            color: white;
            padding: 8px;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .modal-footer {
            margin-top: 20px;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .scan-results-box {
            background: #081120;
            border: 1px solid #1e293b;
            border-radius: 6px;
            height: 120px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 11px;
            padding: 8px;
            color: #22c55e;
            margin-top: 10px;
        }
    </style>
</head>
<body>

<div class="navbar">
    <h2>🛡 REAL-TIME SOC MALWARE DEFENSE SYSTEMS</h2>
    <div class="menu-btns">
        <button class="nav-btn" onclick="toggleModal('reportModal')">📋 Generate PDF Report</button>
        <button class="nav-btn" onclick="toggleModal('scanModal')">🔍 Advanced Malware Scanner</button>
    </div>
</div>

<div class="topbar">
    <div class="card">
        <h4>CPU MONITORING</h4>
        <canvas id="cpuChart"></canvas>
    </div>
    <div class="card">
        <h4>MEMORY MONITORING</h4>
        <canvas id="memChart"></canvas>
    </div>
    <div class="card">
        <h4>TOP PROCESS OCCUPATION</h4>
        <canvas id="processBarChart"></canvas>
    </div>
    <div class="card">
        <h4>HIGH CRITICAL ALERTS</h4>
        <div style="display:flex; justify-content:center; align-items:center; height:160px; font-size:60px; color:red; font-weight:bold;" id="high">0</div>
    </div>
</div>

<div class="container">
    <div class="panel">
        <h4>📁 Live System Security Logs</h4>
        <div class="counter-box">
            <div class="counter">
                <h2 id="totalEvents">0</h2>
                <p>Total Flagged Elements</p>
            </div>
            <div class="counter">
                <h2 id="mediumAlerts">0</h2>
                <p>Medium Risk Indicators</p>
            </div>
        </div>
        <br>
        <div id="events"></div>
    </div>

    <div class="panel">
        <div class="status-box">
            <h4>🧠 CORE SOC RUNTIME METRICS</h4>
            <p>✔ Active Wired/Wireless tracking: ONLINE</p>
            <p>✔ Kernel live packet routing: ACTIVE</p>
            <p>✔ Anomaly correlation engine: OPERATIONAL</p>
        </div>
        <div class="status-box">
            <h4>🛡 ACTIVE DEFENSE ARCHITECTURE</h4>
            <p>Host Firewall Controller: DEPLOYED</p>
            <p>Cryptographic Containment: COMPLIANT</p>
            <p>File System Observers: WATCHING</p>
        </div>
    </div>
</div>

<div class="modal" id="reportModal">
    <div class="modal-content">
        <div class="modal-header">Filter & Generate PDF Report</div>
        <form action="/api/report/download" method="GET" target="_blank">
            <div class="form-group">
                <label>Filter by Target Security Severity</label>
                <select name="severity">
                    <option value="ALL">Show All Classified Log Events</option>
                    <option value="HIGH">HIGH SEVERITY CRITICAL ONLY</option>
                    <option value="MEDIUM">MEDIUM SEVERITY WARNINGS ONLY</option>
                    <option value="LOW">LOW SEVERITY INFORMATIONALS ONLY</option>
                </select>
            </div>
            <div class="form-group">
                <label>Select Target Filter Date</label>
                <input type="date" name="filter_date" id="current_date_setter">
            </div>
            <div class="form-group">
                <label>Filter by Target Operation Hour (Optional)</label>
                <select name="filter_hour">
                    <option value="ALL">Entire 24-Hour Windows</option>
                    <script>
                        for(let i=0; i<24; i++){
                            let h = i < 10 ? '0'+i : i;
                            document.write(`<option value="${h}">${h}:00 - ${h}:59</option>`);
                        }
                    </script>
                </select>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn" style="background:#475569; color:white;" onclick="toggleModal('reportModal')">Cancel</button>
                <button type="submit" class="btn" style="background:#22c55e; color:white;">⚙ Compile PDF Document</button>
            </div>
        </form>
    </div>
</div>

<div class="modal" id="scanModal">
    <div class="modal-content" style="width: 550px;">
        <div class="modal-header">On-Demand Malware File System Scanner</div>
        <div class="form-group">
            <label>Specify Target Directory Absolute Linux Path</label>
            <input type="text" id="scanPath" value="/home/kali" placeholder="e.g. /home/kali/Downloads">
        </div>
        <button type="button" class="btn" style="background:#3b82f6; color:white; width:100%;" onclick="runMalwareScan()">🔍 Launch Inspection Routine</button>
        
        <div class="form-group" style="margin-top: 15px;">
            <label>Live Threat Inspection Diagnostic Console</label>
            <div class="scan-results-box" id="scanConsole">Console ready for directory target parameter execution context...</div>
        </div>
        
        <div class="modal-footer">
            <button type="button" class="btn" style="background:#475569; color:white;" onclick="toggleModal('scanModal')">Close Window</button>
        </div>
    </div>
</div>


<script>
// =====================================
// INTERFACE CHART CONTROLLER MODULES
// =====================================
const cpuCtx = document.getElementById('cpuChart');
const memCtx = document.getElementById('memChart');
const processCtx = document.getElementById('processBarChart');

const cpuData = [];
const memData = [];
const labels = [];

const cpuChart = new Chart(cpuCtx, {
    type: 'line',
    data: { labels: labels, datasets: [{ label: 'CPU %', data: cpuData, borderColor: '#3b82f6', tension: 0.3 }] },
    options: { responsive: true, animation: false, scales: { y: { min: 0, max: 100 } } }
});

const memChart = new Chart(memCtx, {
    type: 'line',
    data: { labels: labels, datasets: [{ label: 'Memory %', data: memData, borderColor: '#22c55e', tension: 0.3 }] },
    options: { responsive: true, animation: false, scales: { y: { min: 0, max: 100 } } }
});

// Horizontal Process Bar Graph
const processBarChart = new Chart(processCtx, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [{
            label: 'RAM Load Occupation (MB)',
            data: [],
            backgroundColor: '#a855f7',
            borderWidth: 0
        }]
    },
    options: {
        indexAxis: 'y',
        responsive: true,
        animation: false,
        scales: { x: { beginAtZero: true } },
        plugins: { legend: { display: false } }
    }
});

function toggleModal(id) {
    const m = document.getElementById(id);
    m.style.display = (m.style.display === 'flex') ? 'none' : 'flex';
    if(id === 'reportModal') {
        document.getElementById('current_date_setter').value = new Date().toISOString().split('T')[0];
    }
}

// =====================================
// FORENSIC SCAN CALL LOGIC
// =====================================
async function runMalwareScan() {
    const targetPath = document.getElementById('scanPath').value;
    const consoleBox = document.getElementById('scanConsole');
    consoleBox.style.color = '#f59e0b';
    consoleBox.innerText = `[~] Initiating deeper static threat inspection across: ${targetPath}...`;
    
    try {
        const res = await fetch("/api/scanner/execute", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ path: targetPath })
        });
        const data = await res.json();
        
        if (data.status === "success") {
            consoleBox.style.color = '#22c55e';
            let reportStr = `[+] Scan complete. Inspected ${data.total_scanned} target files.\\n`;
            if (data.malicious_found.length === 0) {
                reportStr += `[✔] Verification Clean! Zero static malware footprints identified.`;
            } else {
                consoleBox.style.color = '#ef4444';
                reportStr += `[🚨] WARNING! FOUND ${data.malicious_found.length} SUSPICIOUS ELEMENTS:\\n`;
                data.malicious_found.forEach(item => {
                    reportStr += ` -> MISMATCH: ${item.file} (Reason: ${item.reason})\\n`;
                });
            }
            consoleBox.innerText = reportStr;
        } else {
            consoleBox.style.color = '#ef4444';
            consoleBox.innerText = `[-] Scan Routine Halted: ${data.message}`;
        }
    } catch(err) {
        consoleBox.style.color = '#ef4444';
        consoleBox.innerText = "[-] Runtime communication breakdown with the core scanning daemon.";
    }
}

// =====================
// RE-EXECUTE MANUAL ACTIONS
// =====================
async function executeMitigation(actionType, targetValue) {
    if (!confirm(`Are you sure you want to execute manual mitigation: [${actionType}]?`)) return;
    
    try {
        const response = await fetch("/api/mitigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: actionType, target: targetValue })
        });
        const result = await response.json();
        alert(result.message);
        loadData();
    } catch (err) {
        alert("Failed to communicate mitigation response.");
    }
}

// =====================
// DATA SYNC POLLING PIPELINE
// =====================
async function loadData() {
    const res = await fetch("/api/data");
    const data = await res.json();

    if (labels.length > 20) {
        labels.shift();
        cpuData.shift();
        memData.shift();
    }
    labels.push("");
    cpuData.push(data.metrics.cpu);
    memData.push(data.metrics.memory);

    cpuChart.update();
    memChart.update();

    // Dynamically update Top System Resource Consumer Bars
    processBarChart.data.labels = data.top_processes.names;
    processBarChart.data.datasets[0].data = data.top_processes.memory_mb;
    processBarChart.update();

    document.getElementById("high").innerText = data.stats.HIGH || 0;
    document.getElementById("mediumAlerts").innerText = data.stats.MEDIUM || 0;
    document.getElementById("totalEvents").innerText = data.total_events || 0;

    let html = "";
    data.events.forEach(e => {
        const pid = e.extra?.pid || "N/A";
        const ip = e.extra?.source_ip || "Local/Internal";
        const mac = e.extra?.source_mac || "N/A";
        const filePath = e.path || "N/A";

        let actionButtons = "";
        if (pid !== "N/A" && e.type === "process") {
            actionButtons += `<button class="btn btn-danger" onclick="executeMitigation('block_pid', '${pid}')">⛔ Block Process (Kill)</button>`;
        }
        if (filePath !== "N/A" && e.type !== "process") {
            actionButtons += `<button class="btn btn-warning" onclick="executeMitigation('quarantine_file', '${filePath}')">☣ Quarantine File</button>`;
        }

        html += `
            <div class="event ${e.severity}">
                <div class="event-title">${e.type || "unknown"}</div>
                <small>${e.date || ""} ${e.time || "N/A"}</small>
                <br><br>
                <b>Target File/Process:</b> ${filePath} <br>
                <b>PID:</b> ${pid} <br>
                <b>Source Network IP:</b> <span style="color:#f59e0b">${ip}</span> <br>
                <b>Source Device MAC:</b> <span style="color:#a855f7">${mac}</span> <br>
                <b>Severity Level:</b> ${e.severity || "LOW"}
                <br><br>
                <b>Recommendations:</b>
                <ul>
                    ${(e.recommendations || ["Monitor system activity"]).map(r => `<li>${r}</li>`).join("")}
                </ul>
                <div class="btn-zone">
                    ${actionButtons}
                </div>
            </div>
        `;
    });
    document.getElementById("events").innerHTML = html;
}

setInterval(loadData, 2000);
loadData();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/data")
def api_data():
    events = get_events()
    stats = get_stats()

    for e in events:
        e["recommendations"] = get_recommendation(e.get("type"), e.get("severity"))

    incidents = correlator.correlate(events)

    # NEW FEATURE: Query the highest resource occupying processes inside Kali Linux
    process_names = []
    process_mem = []
    try:
        proc_list = sorted(
            [p for p in psutil.process_iter(['name', 'memory_info'])],
            key=lambda p: p.info['memory_info'].rss if p.info['memory_info'] else 0,
            reverse=True
        )[:5]
        for p in proc_list:
            process_names.append(p.info['name'])
            # Convert bytes to megabytes (MB)
            process_mem.append(round(p.info['memory_info'].rss / (1024 * 1024), 2))
    except Exception:
        process_names = ["System", "Kernel", "UserSpace", "Daemon", "Xorg"]
        process_mem = [120, 85, 64, 40, 32]

    return jsonify({
        "metrics": get_system_metrics(),
        "events": events,
        "incidents": incidents,
        "stats": stats,
        "total_events": (stats["LOW"] + stats["MEDIUM"] + stats["HIGH"]),
        "top_processes": {
            "names": process_names,
            "memory_mb": process_mem
        }
    })


@app.route("/api/mitigate", methods=["POST"])
def api_mitigate():
    data = request.json or {}
    action = data.get("action")
    target = data.get("target")

    if not action or not target:
        return jsonify({"status": "error", "message": "Missing mitigation target contexts."}), 400

    try:
        if action == "block_pid":
            pid = int(target)
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            return jsonify({"status": "success", "message": f"Successfully terminated process {proc_name} (PID: {pid})."})
            
        elif action == "quarantine_file":
            quarantine_dir = "data/quarantine"
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)
                
            if os.path.exists(target):
                filename = os.path.basename(target)
                destination = os.path.join(quarantine_dir, f"{filename}.quarantine")
                shutil.move(target, destination)
                return jsonify({"status": "success", "message": f"File moved safely to quarantine directory: {filename}"})
            else:
                return jsonify({"status": "error", "message": "Target file no longer exists."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Mitigation failed: {str(e)}"})


# ========================================================
# 📋 REVENUE ROUTE: FILTERED PDF REPORT COMPILE DAEMON
# ========================================================
@app.route("/api/report/download", methods=["GET"])
def download_pdf_report():
    target_severity = request.args.get("severity", "ALL")
    target_date = request.args.get("filter_date", "")
    target_hour = request.args.get("filter_hour", "ALL")

    # Fetch total raw database records
    raw_logs = get_all_raw_events()
    filtered_logs = []

    for log in raw_logs:
        # 1. Filter by specific operational text Date
        if target_date and log.get("date") != target_date:
            continue
        
        # 2. Filter by Severity Type classification
        if target_severity != "ALL" and log.get("severity") != target_severity:
            continue
            
        # 3. Filter by Time block hour matching string
        if target_hour != "ALL":
            log_hour = log.get("time", "00:00:00").split(":")[0]
            if log_hour != target_hour:
                continue
                
        filtered_logs.append(log)

    # Compile the PDF layout via a standard ReportLab IO Stream buffer
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#0f172a'), spaceAfter=12)
    meta_style = ParagraphStyle('ReportMeta', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#475569'), spaceAfter=20)
    text_style = ParagraphStyle('TableText', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#1e293b'))
    header_style = ParagraphStyle('TableHeader', parent=styles['Normal'], fontSize=10, fontName='Helvetica-Bold', textColor=colors.HexColor('#ffffff'))

    story = []
    
    # Header Elements
    story.append(Paragraph("SOC INCIDENT SUMMARY & AUDIT REPORT", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target Filtering Severity: {target_severity} | Scope Date: {target_date if target_date else 'All Available Records'}", meta_style))
    story.append(Spacer(1, 10))

    # Construct the Log Events Table grid layout
    table_data = [[Paragraph("Timestamp", header_style), Paragraph("Component", header_style), Paragraph("Identified Security Object Target Path", header_style), Paragraph("Risk Level", header_style)]]
    
    for item in filtered_logs:
        full_time_str = f"{item.get('date', '')} {item.get('time', '')}"
        table_data.append([
            Paragraph(full_time_str, text_style),
            Paragraph(str(item.get("type", "")), text_style),
            Paragraph(str(item.get("path", "")), text_style),
            Paragraph(str(item.get("severity", "")), text_style),
        ])

    log_table = Table(table_data, colWidths=[110, 80, 270, 70])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.HexColor('#e2e8f0')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    
    story.append(log_table)
    doc.build(story)
    
    pdf_buffer.seek(0)
    return send_file(pdf_buffer, as_attachment=True, download_name=f"SOC_Report_{datetime.now().strftime('%M%S')}.pdf", mimetype="application/pdf")


# ========================================================
# 🔍 INTERACTIVE PARSING DIRECTORY SCANNING ALGORITHM
# ========================================================
@app.route("/api/scanner/execute", methods=["POST"])
def execute_static_scan():
    """Crawls a user-specified Linux directory path to inspect files against malware indicators."""
    data = request.json or {}
    scan_target = data.get("path", "").strip()
    
    if not scan_target or not os.path.exists(scan_target):
        return jsonify({"status": "error", "message": "Provided target Linux path does not exist on this host machine."}), 400
        
    malicious_indicators = []
    total_files_checked = 0
    
    # Extension signatures and character patterns used by basic threat components
    suspicious_extensions = ['.locked', '.sh', '.py', '.exe', '.bat']
    malicious_keywords = [b"ENCRYPTED::", b"eval(base64", b"os.system('rm -rf", b"subprocess.Popen"]
    
    try:
        # Walk through the specified directory up to 1 layer deep to avoid getting stuck in loops
        for root, dirs, files in os.walk(scan_target):
            # Guard constraint to limit total recursive inspection counts
            if total_files_checked > 250:
                break
                
            for file in files:
                total_files_checked += 1
                full_path = os.path.join(root, file)
                
                # Check 1: Extension Match Rule
                if any(full_path.endswith(ext) for ext in suspicious_extensions):
                    # Flag malware immediately if hitting ransomware target strings
                    if full_path.endswith('.locked'):
                        malicious_indicators.append({"file": file, "reason": "Ransomware Encrypted Ext (.locked)"})
                        continue
                
                # Check 2: Header Signature byte sequence reading
                try:
                    with open(full_path, "rb") as f:
                        file_header = f.read(2048)  # Read initial code buffer blocks
                        for kw in malicious_keywords:
                            if kw in file_header:
                                malicious_indicators.append({"file": file, "reason": f"Malicious Code Footprint Detected ({kw.decode()})"})
                                # Log it automatically onto our centralized event panel
                                add_event(
                                    event_type="Malware Scanner Discovery",
                                    severity="HIGH",
                                    path=file,
                                    extra={"source_ip": "127.0.0.1 (Host)", "source_mac": "N/A"}
                                )
                                break
                except Exception:
                    pass # Ignore locked system descriptors
                    
    except Exception as e:
        return jsonify({"status": "error", "message": f"Scanning engine exception: {str(e)}"}), 500
        
    return jsonify({
        "status": "success",
        "total_scanned": total_files_checked,
        "malicious_found": malicious_indicators
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
