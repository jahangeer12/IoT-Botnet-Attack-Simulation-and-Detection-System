#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <fcntl.h>

// ===================== CONFIG =====================
const char* ssid       = "OnePlus";
const char* password   = "omkar@123";
const char* laptopIP   = "10.52.57.13";
const int   laptopPort = 8080;

#define POOL_SIZE 6
#define SERVER_PORT 80
#define STAT_INTERVAL_MS 5000

// ===================== STATE =====================
static char serverIP[32] = {0};
static bool startSending = false;
static uint32_t sendInterval = 0;

static WiFiClient controlClient;

// RAW socket pool
static int sockets[POOL_SIZE];
static bool connected[POOL_SIZE];
static uint32_t lastUse[POOL_SIZE];

// stats
static uint32_t packetsSent = 0;
static uint32_t packetsFailed = 0;
static uint32_t bytesSent = 0;
static uint32_t startTime = 0;
static uint32_t lastStat = 0;

// ================================================================
// WIFI
// ================================================================
void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(ssid, password);

  Serial.print("[WiFi] Connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print(".");
  }

  Serial.printf("\n[WiFi] Connected: %s RSSI:%d\n",
                WiFi.localIP().toString().c_str(),
                WiFi.RSSI());
}

// ================================================================
// CONTROL CHANNEL
// ================================================================
bool connectToLaptop() {
  controlClient.stop();
  delay(50);

  if (!controlClient.connect(laptopIP, laptopPort)) {
    Serial.println("[Ctrl] Connect failed");
    return false;
  }

  controlClient.setNoDelay(true);

  controlClient.printf(
    "ESP32_CONNECTED\r\nESP_IP:%s\r\nRSSI:%d\r\n",
    WiFi.localIP().toString().c_str(),
    WiFi.RSSI()
  );

  Serial.println("[Ctrl] Connected");
  return true;
}

// ================================================================
// RAW SOCKET
// ================================================================
bool createSocket(int i) {
  sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
  if (sockets[i] < 0) return false;

  fcntl(sockets[i], F_SETFL, O_NONBLOCK);

  int flag = 1;
  setsockopt(sockets[i], IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(SERVER_PORT);
  server.sin_addr.s_addr = inet_addr(serverIP);

  int res = connect(sockets[i], (struct sockaddr*)&server, sizeof(server));

  if (res < 0 && errno != EINPROGRESS) {
    close(sockets[i]);
    return false;
  }

  connected[i] = true;
  lastUse[i] = millis();
  return true;
}

// ================================================================
// INIT POOL
// ================================================================
void initPool() {
  for (int i = 0; i < POOL_SIZE; i++) {
    connected[i] = false;
  }
}

// ================================================================
// SEND PACKET
// ================================================================
inline void sendPacket(int i) {

  if (!connected[i]) {
    if (!createSocket(i)) return;
  }

  char buffer[256];

  int len = snprintf(buffer, sizeof(buffer),
      "POST /index.php HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Connection: keep-alive\r\n"
      "Content-Type: application/x-www-form-urlencoded\r\n"
      "Content-Length: 60\r\n\r\n"
      "device=ESP32&value=%d&slot=%d&pkt=%lu&ms=%lu&rssi=%d",
      serverIP,
      analogRead(A0),
      i,
      (unsigned long)packetsSent,
      (unsigned long)millis(),
      WiFi.RSSI());

  int sent = send(sockets[i], buffer, len, MSG_DONTWAIT);

  if (sent < 0) {
    packetsFailed++;
    connected[i] = false;
    close(sockets[i]);
    return;
  }

  packetsSent++;
  bytesSent += sent;
  lastUse[i] = millis();
}

// ================================================================
// DRAIN RESPONSES (NON-BLOCKING)
// ================================================================
void drainResponses() {
  char buf[128];

  for (int i = 0; i < POOL_SIZE; i++) {
    if (!connected[i]) continue;

    int len = recv(sockets[i], buf, sizeof(buf), MSG_DONTWAIT);

    if (len <= 0) continue;

    // detect connection close
    for (int j = 0; j < len - 15; j++) {
      if (memcmp(&buf[j], "Connection: close", 17) == 0) {
        connected[i] = false;
        close(sockets[i]);
      }
    }
  }
}

// ================================================================
// COMMAND HANDLER
// ================================================================
void sendCtrl(const char* msg) {
  if (controlClient.connected()) {
    controlClient.println(msg);
  }
}

void handleCommand(char* cmd) {

  if (strncmp(cmd, "SERVER:", 7) == 0) {
    strncpy(serverIP, cmd + 7, sizeof(serverIP) - 1);

    initPool();

    sendCtrl("OK SERVER_SET");

  } else if (strcmp(cmd, "START") == 0) {

    startSending = true;
    packetsSent = packetsFailed = bytesSent = 0;
    startTime = millis();

    sendCtrl("OK STARTED");

  } else if (strcmp(cmd, "STOP") == 0) {

    startSending = false;
    sendCtrl("OK STOPPED");

  } else if (strncmp(cmd, "INTERVAL:", 9) == 0) {

    sendInterval = atoi(cmd + 9);
    sendCtrl("OK INTERVAL");

  } else if (strcmp(cmd, "STATUS") == 0) {

    uint32_t up = (millis() - startTime) / 1000 + 1;

    controlClient.printf(
      "STATUS:%s\r\nSERVER_IP:%s\r\nPACKETS:%lu\r\nRATE:%lu\r\n",
      startSending ? "STARTED" : "STOPPED",
      serverIP,
      (unsigned long)packetsSent,
      (unsigned long)(packetsSent / up)
    );

  } else if (strcmp(cmd, "RESET") == 0) {

    startSending = false;

    for (int i = 0; i < POOL_SIZE; i++) {
      if (connected[i]) close(sockets[i]);
      connected[i] = false;
    }

    sendCtrl("OK RESET");
  }
}

// ================================================================
// READ COMMANDS (FAST)
// ================================================================
void readCommands() {
  static char buffer[128];
  static int idx = 0;

  while (controlClient.available()) {
    char c = controlClient.read();

    if (c == '\n') {
      buffer[idx] = 0;
      handleCommand(buffer);
      idx = 0;
    } else if (idx < sizeof(buffer) - 1) {
      buffer[idx++] = c;
    }
  }
}

// ================================================================
// SETUP
// ================================================================
void setup() {
  Serial.begin(115200);

  connectWiFi();
  connectToLaptop();
  initPool();

  Serial.println("[System] RAW + Control Ready");
}

// ================================================================
// LOOP
// ================================================================
void loop() {

  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
    connectToLaptop();
    return;
  }

  if (!controlClient.connected()) {
    connectToLaptop();
    return;
  }

  readCommands();
  drainResponses();

  static uint32_t lastSend = 0;

  if (startSending && serverIP[0] != 0) {
    if (millis() - lastSend >= sendInterval) {
      lastSend = millis();

      for (int i = 0; i < POOL_SIZE; i++) {
        sendPacket(i);
      }
    }
  }

  if (millis() - lastStat > STAT_INTERVAL_MS) {
    lastStat = millis();

    Serial.printf("[Stats] Sent:%lu Failed:%lu\n",
      (unsigned long)packetsSent,
      (unsigned long)packetsFailed);
  }
}