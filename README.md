# 🛡️ IoT Botnet Attack Simulation and Detection System

![C++](https://img.shields.io/badge/C++-17-blue?logo=cplusplus)
![Arduino](https://img.shields.io/badge/Arduino-ESP32-teal?logo=arduino)
![Qt5](https://img.shields.io/badge/Qt-5-brightgreen?logo=qt)
![Platform](https://img.shields.io/badge/IDS-Linux-informational?logo=linux)
![Attacker](https://img.shields.io/badge/Control%20Panel-Windows-blue?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)

A three-component system that **simulates real IoT botnet-style HTTP flood attacks** from an ESP32 device and **detects them in real time** using an adaptive statistical IDS running on Linux. A Windows C++ control panel orchestrates the ESP32 attacker over a TCP command channel.

---

## 📖 Table of Contents

- [System Overview](#system-overview)
- [Architecture](#architecture)
- [Components](#components)
  - [1. ESP32 Attacker (newesp32.ino)](#1-esp32-attacker-newesp32ino)
  - [2. Windows Control Panel (attacker.cpp)](#2-windows-control-panel-attackercpp)
  - [3. Linux IDS (ids.cpp)](#3-linux-ids-idscpp)
- [Detection Engines](#detection-engines)
- [Threat Classification](#threat-classification)
- [Prerequisites & Build](#prerequisites--build)
- [Setup & Usage](#setup--usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## 🔍 System Overview

This project demonstrates a full-cycle IoT botnet attack and its detection:

1. An **ESP32 microcontroller** connects to Wi-Fi and launches a pool of simultaneous TCP connections, flooding an Apache/HTTP target server with rapid POST requests.
2. A **Windows GUI (Control Panel)** communicates with the ESP32 over a persistent TCP control channel to configure the target IP, set packet intervals, and start/stop the attack.
3. A **Linux IDS** (Qt5 + libpcap) sniffs live network traffic, builds per-IP statistical baselines using Welford's online algorithm, and detects anomalies across 7 independent detection engines — with instant software-level blocking and async `iptables` enforcement.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ATTACKER SIDE                             │
│                                                                  │
│  ┌─────────────────┐   TCP :8080    ┌─────────────────────────┐  │
│  │  Windows GUI    │◄──────────────►│  ESP32 (Arduino)        │  │
│  │  attacker.cpp   │  Control cmds  │  newesp32.ino           │  │
│  │                 │  Status / IP   │                         │  │
│  └─────────────────┘                │  Socket pool (6 slots)  │  │
│                                     │  HTTP POST flood        │  │
└─────────────────────────────────────┼─────────────────────────┘  
                                      │ TCP :80 (HTTP flood)
                                      ▼
                          ┌───────────────────────┐
                          │  Target HTTP Server   │
                          │  (Apache / any HTTP)  │
                          └──────────┬────────────┘
                                     │ (same network)
                                     ▼
┌──────────────────────────────────────────────────────────────────┐
│                        DEFENDER SIDE                             │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Linux IDS  (ids.cpp  — Qt5 + libpcap)                  │    │
│  │                                                          │    │
│  │  pcap sniffer ──► packetHandler ──► per-IP IPStats       │    │
│  │  (sniffer thread)   [software block                      │    │
│  │                      checked first]                      │    │
│  │                                                          │    │
│  │  UI timer (1 s) ──► classify() ──► ThreatInfo           │    │
│  │   Welford baseline     7 detection engines               │    │
│  │   z-score scoring      NONE/LOW/MEDIUM/HIGH/CRITICAL     │    │
│  │                                                          │    │
│  │  Block action ──► g_blockedIPs (instant drop)            │    │
│  │               └─► iptables -A INPUT -s <IP> -j DROP      │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Components

### 1. ESP32 Attacker (`newesp32.ino`)

An Arduino sketch for the ESP32 that acts as a lightweight IoT botnet node.

**Key features:**
- Connects to Wi-Fi and immediately establishes a **persistent TCP control channel** to the Windows control panel (port 8080).
- Maintains a **pool of 6 non-blocking TCP sockets** (`SOCK_STREAM`) to the target HTTP server for parallel flooding.
- Sends rapid **HTTP POST requests** (`POST /index.php`) carrying sensor data (analog pin A0, slot number, packet count, timestamp, RSSI).
- Reports live stats (packets sent, failed, bytes sent) every 5 seconds over the Serial monitor.
- Supports **auto-reconnect** for both Wi-Fi and the control channel.

**Commands accepted (from control panel):**

| Command | Action |
|---------|--------|
| `SERVER:<ip>` | Set the target HTTP server IP and reinitialise the socket pool |
| `START` | Begin flooding; reset counters |
| `STOP` | Halt packet transmission |
| `INTERVAL:<ms>` | Set the inter-burst delay in milliseconds |
| `STATUS` | Reply with current state, packets sent, and rate |
| `RESET` | Stop sending and close all sockets |

**Configuration (top of sketch):**

```cpp
const char* ssid       = "YourSSID";
const char* password   = "YourPassword";
const char* laptopIP   = "10.52.57.13";   // Windows control panel IP
const int   laptopPort = 8080;
```

---

### 2. Windows Control Panel (`attacker.cpp`)

A native Win32 GUI application that acts as the **command-and-control (C&C) server** for the ESP32.

**Key features:**
- Listens on **TCP port 8080** for an incoming ESP32 connection (non-blocking accept on a worker thread so the UI stays responsive).
- Displays the ESP32's IP address once connected.
- Sends typed commands over the persistent TCP channel using a `CRITICAL_SECTION`-protected send to guard against concurrent writes.
- Receives and parses status lines from the ESP32 (`STATUS:`, `ESP_IP:`, etc.) on a dedicated receive thread, updating the UI via `PostMessage` for thread safety.
- Provides a scrolling log window and a status bar.

**GUI controls:**

| Control | Description |
|---------|-------------|
| Apache IP field | IP address of the HTTP target server |
| Interval (ms) field | Packet burst interval (default 2000 ms) |
| **Listen for ESP32** | Open server socket and wait for ESP32 to connect |
| **Set Apache IP** | Push `SERVER:<ip>` command to ESP32 |
| **Set Interval** | Push `INTERVAL:<ms>` command to ESP32 |
| **Start Sending** | Push `START` command |
| **Stop Sending** | Push `STOP` command |
| **Get Status** | Push `STATUS` command; response shown in log |
| **Clear Log** | Clear the log window |

**Build (MSVC or MinGW):**

```bat
g++ attacker.cpp -o attacker.exe -lws2_32 -mwindows
```
or with MSVC:
```bat
cl attacker.cpp /link ws2_32.lib user32.lib gdi32.lib
```

---

### 3. Linux IDS (`ids.cpp`)

An adaptive, real-time Intrusion Detection System with a Qt5 GUI and libpcap packet capture.

**Version:** IDS v4.1 — Adaptive Baseline + Instant Software Block

**Key features:**
- **Live packet capture** on the primary network interface via `pcap_open_live`.
- **Software-level instant block**: blocked IPs are checked *before* any stat is counted inside `packetHandler`. Zero packets leak through after a block decision.
- **Async iptables enforcement**: `iptables -A INPUT -s <IP> -j DROP` runs in a `QProcess` child process so the UI is never blocked.
- **Per-IP IP Registry**: every seen IP is recorded with total packets, last seen time, threat level, detected reasons, and status (ACTIVE / BLOCKED).
- **Inline block/unblock buttons** per row plus bulk block/unblock on selected rows.
- **Event Log** tab with timestamped BLOCK, UNBLOCK, AUTO-BLOCK, and INFO entries.
- **Stat cards**: Total Packets · Unique IPs · Threats · Blocked · Registry size.
- **Global Traffic Spike engine**: if global packets/s z-score spikes AND a single IP accounts for >40 % of traffic AND that IP is already HIGH or CRITICAL, it is auto-blocked (10-second cooldown per IP).
- **Warmup period**: for the first 30 samples, fallback hard limits are used; afterwards Welford baselines take over.
- **Configurable parameters** from the UI: z-score threshold (default 3.0 σ), baseline window (default 300 s), auto-block toggle, botnet concurrency count.

---

## 🔬 Detection Engines

All engines operate **per source IP, evaluated every second**:

| Engine | Metric tracked | Notes |
|--------|---------------|-------|
| **SYN Flood** | SYN packets/s | TCP SYN without ACK |
| **Port Scan** | Distinct destination ports/s | Large port diversity = scanning |
| **ICMP Flood** | ICMP packets/s | Ping floods, Smurf variants |
| **UDP Flood** | UDP packets/s | Volumetric UDP flood |
| **Brute Force** | Hits on auth ports/s | Ports: 21 (FTP), 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC) |
| **Rate Anomaly** | Total packets/s | Catches generic high-rate sources |
| **Botnet Heuristic** | Count of simultaneous HIGH+ IPs | N or more IPs at HIGH or CRITICAL level simultaneously |
| **Global Spike** *(v4.1)* | Global packets/s z-score + IP dominance | Auto-blocks dominant IP if global spike is detected |

---

## 📊 Threat Classification

Each IP is scored by summing weighted z-score contributions from every fired engine:

| Score range | Threat level | Colour |
|-------------|-------------|--------|
| 0 | NORMAL | Grey |
| 1 – 19 | LOW | Green |
| 20 – 39 | MEDIUM | Yellow |
| 40 – 59 | HIGH | Orange |
| ≥ 60 | CRITICAL | Red |

Z-score tiers per engine (warmed-up mode):

| z relative to threshold | Score added |
|-------------------------|-------------|
| > 1× threshold | base (25–45 pts) |
| > 1.5× threshold | boosted (45–60 pts) |
| > 2.5× threshold | extreme (60–75 pts) |

---

## ⚙️ Prerequisites & Build

### IDS (Linux)

**Dependencies:**
- Qt 5 (Widgets + Charts)
- libpcap
- GCC with C++17 support

**Install (Ubuntu/Debian):**
```bash
sudo apt install qt5-default libqt5charts5-dev libpcap-dev g++
```

**Build:**
```bash
g++ ids.cpp -o ids -fPIC \
    $(pkg-config --cflags --libs Qt5Widgets Qt5Charts) \
    -lpcap -std=c++17
```

**Run (requires root for pcap):**
```bash
sudo ./ids
```

---

### Windows Control Panel

**Dependencies:** Windows SDK (Winsock2)

**Build (MinGW):**
```bat
g++ attacker.cpp -o attacker.exe -lws2_32 -mwindows
```

---

### ESP32 Firmware

**Requirements:**
- Arduino IDE with **ESP32 board package** installed
- Board: **ESP32 Dev Module** (or equivalent)

**Flash:**
1. Open `newesp32.ino` in the Arduino IDE.
2. Edit the Wi-Fi credentials and `laptopIP` at the top of the file.
3. Select the correct COM port and board.
4. Upload.

---

## 🚀 Setup & Usage

### Step 1 — Start the IDS on Linux
```bash
sudo ./ids
```
The IDS auto-detects the primary network interface and begins sniffing immediately.

### Step 2 — Launch the Windows Control Panel
Run `attacker.exe`, then click **Listen for ESP32**. The status bar shows *"Waiting for ESP32…"*.

### Step 3 — Power on the ESP32
The ESP32 connects to Wi-Fi and dials back to the Windows control panel. The panel shows *"ESP32 Connected"* and displays the ESP32's IP.

### Step 4 — Configure the attack target
1. In the control panel, enter the **Apache/HTTP server IP** and click **Set Apache IP**.
2. Optionally change the **Interval (ms)** and click **Set Interval**.

### Step 5 — Start the flood
Click **Start Sending**. The ESP32 opens 6 parallel sockets and begins sending HTTP POST requests to the target.

### Step 6 — Observe detection on the IDS
Switch to the Linux machine. Within seconds the target's IP will appear in the IDS traffic table. As the flood continues:
- The threat level escalates: LOW → MEDIUM → HIGH → CRITICAL.
- With **Auto Block** enabled, the IDS blocks the source automatically.
- A software drop is applied instantly; `iptables` enforces it at the kernel level.

### Step 7 — Stop and reset
Click **Stop Sending** (or **Reset**) in the control panel to halt the ESP32.

---

## 📁 Project Structure

```
IoT-Botnet-Attack-Simulation-and-Detection-System/
│
├── newesp32.ino        # ESP32 Arduino firmware — Wi-Fi + socket pool + HTTP flood
├── attacker.cpp        # Windows Win32 GUI — C&C control panel (TCP :8080)
├── ids.cpp             # Linux Qt5 IDS — pcap sniffer + adaptive baseline + block
└── README.md
```

---

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push and open a Pull Request.

Please follow the existing code style and include comments for any new detection logic.

---

## ⚠️ Disclaimer

This project is intended solely for **educational and research purposes** in controlled, isolated lab environments. Simulating network attacks against systems you do not own or do not have explicit written permission to test is **illegal** under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.

**Never run the attacker components against production systems or public networks.**
