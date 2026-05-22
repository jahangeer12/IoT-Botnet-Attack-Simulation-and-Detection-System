#include <winsock2.h>
#include <windows.h>
#include <string>
#include <sstream>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define WM_LOGMSG (WM_USER + 1)   // custom message for thread-safe logging

// ===================== GLOBALS =====================
SOCKET serverSock = INVALID_SOCKET;
SOCKET clientSock = INVALID_SOCKET;

std::atomic<bool> connected(false);
std::atomic<bool> serverRunning(false);

HWND hWnd;
HWND hLog, hServerIP, hInterval, hEspIP, hStatusBar;
CRITICAL_SECTION sendLock;   // guard concurrent sends

// ===================== THREAD-SAFE LOG =====================
// Called from any thread — posts to the UI thread via WM_LOGMSG.
void log(const std::string& text) {
    // Heap-allocate so the string survives across threads
    std::string* msg = new std::string(text);
    PostMessage(hWnd, WM_LOGMSG, 0, (LPARAM)msg);
}

void appendLog(const std::string& text) {
    int len = GetWindowTextLength(hLog);
    SendMessage(hLog, EM_SETSEL, len, len);
    SendMessage(hLog, EM_REPLACESEL, FALSE, (LPARAM)(text + "\r\n").c_str());
    SendMessage(hLog, WM_VSCROLL, SB_BOTTOM, 0);
}

// ===================== STATUS BAR =====================
void setStatus(const std::string& text) {
    SetWindowText(hStatusBar, text.c_str());
}

// ===================== RECEIVE THREAD =====================
DWORD WINAPI recvThread(LPVOID) {
    char buffer[4096];
    std::string leftover;   // holds partial lines across recv() calls

    while (connected) {
        int bytes = recv(clientSock, buffer, sizeof(buffer) - 1, 0);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            leftover += buffer;

            // Process complete lines
            size_t pos;
            while ((pos = leftover.find('\n')) != std::string::npos) {
                std::string line = leftover.substr(0, pos);
                leftover.erase(0, pos + 1);

                // Strip carriage return if present
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;

                // Parse known status blocks for the UI
                if (line.find("STATUS:") == 0) {
                    log("─── STATUS ────────────────────────");
                } else if (line.find("ESP_IP:") == 0) {
                    std::string ip = line.substr(7);
                    // Update ESP IP label on UI thread
                    std::string* s = new std::string(ip);
                    PostMessage(hWnd, WM_USER + 2, 0, (LPARAM)s);
                }

                log(line);
            }
        } else if (bytes == 0) {
            log("📴 ESP32 closed the connection.");
            break;
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                log("❌ recv error: " + std::to_string(err));
                break;
            }
        }
    }

    connected = false;
    closesocket(clientSock);
    clientSock = INVALID_SOCKET;
    log("🔌 Disconnected. Click 'Listen' to wait for next ESP32.");
    setStatus("Disconnected");
    return 0;
}

// ===================== ACCEPT THREAD =====================
// Runs in background so the UI stays responsive during accept().
DWORD WINAPI acceptThread(LPVOID) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == INVALID_SOCKET) {
        log("❌ Socket create failed: " + std::to_string(WSAGetLastError()));
        serverRunning = false;
        return 0;
    }

    // Allow port reuse so restarting doesn't hit TIME_WAIT
    BOOL opt = TRUE;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in server{};
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port        = htons(PORT);

    if (bind(serverSock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        log("❌ Bind failed: " + std::to_string(WSAGetLastError()));
        closesocket(serverSock);
        serverRunning = false;
        return 0;
    }

    listen(serverSock, 1);
    log("🟢 Listening on port " + std::to_string(PORT) + "...");
    setStatus("Waiting for ESP32...");

    // accept() blocks until ESP32 connects — safe because we're on a worker thread
    clientSock = accept(serverSock, NULL, NULL);

    if (clientSock == INVALID_SOCKET) {
        log("❌ Accept failed or server stopped.");
        serverRunning = false;
        return 0;
    }

    // Disable Nagle on the control channel for low-latency commands
    setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));

    connected    = true;
    serverRunning = false;   // accept done; server socket can stay open for re-listen
    log("✅ ESP32 Connected");
    setStatus("ESP32 Connected");

    CreateThread(NULL, 0, recvThread, NULL, 0, NULL);
    return 0;
}

// ===================== SEND (thread-safe) =====================
bool sendCmd(const std::string& cmd) {
    if (!connected || clientSock == INVALID_SOCKET) {
        log("⚠ No ESP32 connected.");
        return false;
    }

    EnterCriticalSection(&sendLock);
    int res = send(clientSock, cmd.c_str(), (int)cmd.length(), 0);
    LeaveCriticalSection(&sendLock);

    if (res == SOCKET_ERROR) {
        log("❌ Send failed: " + std::to_string(WSAGetLastError()));
        connected = false;
        closesocket(clientSock);
        clientSock = INVALID_SOCKET;
        setStatus("Send error — disconnected");
        return false;
    }
    return true;
}

// ===================== HELPERS =====================
std::string getEditText(HWND h) {
    char buf[256]{};
    GetWindowText(h, buf, sizeof(buf));
    return buf;
}

void doListen() {
    if (serverRunning) { log("⚠ Already listening."); return; }
    if (connected)     { log("⚠ ESP32 already connected."); return; }
    serverRunning = true;
    CreateThread(NULL, 0, acceptThread, NULL, 0, NULL);
}

void sendServerIP() {
    std::string ip = getEditText(hServerIP);
    if (ip.empty()) { log("⚠ Enter Apache IP first."); return; }
    sendCmd("SERVER:" + ip + "\n");
    log("→ Server IP sent: " + ip);
}

void sendInterval() {
    std::string iv = getEditText(hInterval);
    if (iv.empty()) { log("⚠ Enter interval (ms) first."); return; }
    sendCmd("INTERVAL:" + iv + "\n");
    log("→ Interval set: " + iv + " ms");
}

void startData()  { if (sendCmd("START\n"))   log("→ START sent"); }
void stopData()   { if (sendCmd("STOP\n"))    log("→ STOP sent");  }
void getStatus()  { if (sendCmd("STATUS\n"))  log("→ STATUS requested"); }
void clearLog()   { SetWindowText(hLog, ""); }

// ===================== WINDOW =====================
#define BTN(label, x, y, w, id) \
    CreateWindow("BUTTON", label, WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, x,y,w,28, hwnd,(HMENU)(id),NULL,NULL)

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {

    switch (msg) {

    case WM_CREATE: {
        hWnd = hwnd;
        InitializeCriticalSection(&sendLock);

        int x = 10, y = 10, lw = 480;

        // Row 0: Apache IP
        CreateWindow("STATIC", "Apache IP:", WS_VISIBLE|WS_CHILD, x, y+3, 80, 20, hwnd, NULL, NULL, NULL);
        hServerIP = CreateWindow("EDIT", "",
            WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL,
            95, y, 200, 26, hwnd, NULL, NULL, NULL);
        BTN("Set Apache IP",  300, y, 120, 2);
        y += 36;

        // Row 1: Interval
        CreateWindow("STATIC", "Interval (ms):", WS_VISIBLE|WS_CHILD, x, y+3, 90, 20, hwnd, NULL, NULL, NULL);
        hInterval = CreateWindow("EDIT", "2000",
            WS_VISIBLE|WS_CHILD|WS_BORDER|ES_NUMBER,
            105, y, 90, 26, hwnd, NULL, NULL, NULL);
        BTN("Set Interval", 200, y, 120, 7);
        y += 36;

        // Row 2: Connection
        BTN("Listen for ESP32", x,   y, 140, 1);
        y += 36;

        // Row 3: Data control
        BTN("Start Sending",   x,       y, 130, 3);
        BTN("Stop Sending",    x+140,   y, 130, 4);
        BTN("Get Status",      x+280,   y, 130, 5);
        y += 36;

        // Row 4: Misc
        BTN("Clear Log",       x, y, 100, 6);

        // ESP IP display
        CreateWindow("STATIC", "ESP IP:", WS_VISIBLE|WS_CHILD, x+115, y+5, 50, 20, hwnd, NULL, NULL, NULL);
        hEspIP = CreateWindow("STATIC", "—",
            WS_VISIBLE|WS_CHILD,
            x+165, y+5, 200, 20, hwnd, NULL, NULL, NULL);
        y += 36;

        // Log
        hLog = CreateWindow("EDIT", "",
            WS_VISIBLE|WS_CHILD|WS_BORDER|ES_MULTILINE|ES_READONLY|WS_VSCROLL|ES_AUTOVSCROLL,
            x, y, lw, 280, hwnd, NULL, NULL, NULL);
        y += 290;

        // Status bar
        hStatusBar = CreateWindow("STATIC", "Idle",
            WS_VISIBLE|WS_CHILD|SS_SUNKEN,
            x, y, lw, 22, hwnd, NULL, NULL, NULL);

        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 1: doListen();    break;
        case 2: sendServerIP(); break;
        case 3: startData();   break;
        case 4: stopData();    break;
        case 5: getStatus();   break;
        case 6: clearLog();    break;
        case 7: sendInterval(); break;
        }
        break;

    // Thread-safe log (from recvThread / acceptThread)
    case WM_LOGMSG: {
        std::string* msg2 = reinterpret_cast<std::string*>(lParam);
        appendLog(*msg2);
        delete msg2;
        break;
    }

    // Update ESP IP label from recv thread
    case WM_USER + 2: {
        std::string* ip = reinterpret_cast<std::string*>(lParam);
        SetWindowText(hEspIP, ip->c_str());
        delete ip;
        break;
    }

    case WM_DESTROY:
        connected = false;
        serverRunning = false;
        if (clientSock != INVALID_SOCKET) closesocket(clientSock);
        if (serverSock != INVALID_SOCKET) closesocket(serverSock);
        DeleteCriticalSection(&sendLock);
        WSACleanup();
        PostQuitMessage(0);
        break;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ===================== MAIN =====================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nShow) {

    WNDCLASS wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "ESP32Server";
    RegisterClass(&wc);

    CreateWindow("ESP32Server", "ESP32 Control Panel — v2",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        200, 100,
        520, 560,          // wider to fit new controls
        NULL, NULL, hInst, NULL);

    MSG msg{};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}