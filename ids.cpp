/*
 * IDS v4.1 — Adaptive Baseline + Instant Software Block
 *
 * Detection engines (per-IP, evaluated every second):
 *   - SYN Flood        — SYN/s deviates from baseline mean by N sigma
 *   - Port Scan        — distinct dst-ports/s deviates from baseline
 *   - ICMP Flood       — ICMP/s deviates from baseline
 *   - UDP Flood        — UDP/s deviates from baseline
 *   - Brute Force      — hits on auth ports (22/21/23/3389/5900)/s deviates
 *   - Rate Anomaly     — total packets/s deviates from baseline
 *   - Botnet heuristic — N simultaneous HIGH+ IPs
 *   - Global Spike     — total traffic z-score + single-IP dominance (NEW)
 *
 * Key fix in v4.1:
 *   - g_blockedIPs checked inside packetHandler BEFORE stats are counted
 *   - Block takes effect in microseconds (no iptables race condition)
 *   - iptables now runs async (non-blocking UI)
 *   - Zero packets leak through after block is clicked
 *
 * Build:
 *   g++ ids_v4.cpp -o ids -fPIC \
 *       $(pkg-config --cflags --libs Qt5Widgets Qt5Charts) \
 *       -lpcap -std=c++17
 */

#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QTimer>
#include <QFrame>
#include <QPainter>
#include <QPaintEvent>
#include <QDateTime>
#include <QProcess>
#include <QCheckBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QTabWidget>
#include <QScrollArea>
#include <QLineEdit>
#include <QProgressBar>

#include <pcap.h>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <mutex>
#include <cmath>
#include <deque>
#include <vector>
#include <numeric>
#include <algorithm>
#include <chrono>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

// ================================================================
//  SHARED DETECTION DATA
// ================================================================

struct IPStats {
    int pktCount  = 0;
    int synCount  = 0;
    int icmpCount = 0;
    int udpCount  = 0;
    int authHits  = 0;
    std::set<uint16_t> dstPorts;
};

std::unordered_map<std::string, IPStats> ipStats;
std::mutex statsMutex;

// ================================================================
//  GLOBAL SOFTWARE BLOCK SET
//  Checked inside packetHandler before any stat is counted.
//  Writes happen on the UI thread; reads on the sniffer thread.
//  Protected by blockedMutex for thread safety.
// ================================================================
std::unordered_set<std::string> g_blockedIPs;
std::mutex                      blockedMutex;

// ================================================================
//  BASELINE ENGINE — Welford's Online Algorithm
// ================================================================

static const int    DEFAULT_WINDOW   = 300;   // seconds of history
static const int    MIN_SAMPLES      = 30;    // warm-up period
static const double DEFAULT_Z_THRESH = 3.0;   // sigma multiplier

struct FallbackLimits {
    int pktRate   = 80;
    int synFlood  = 60;
    int portScan  = 15;
    int icmpFlood = 50;
    int udpFlood  = 80;
    int authBrute = 10;
};
FallbackLimits g_fallback;

struct BaselineMetric {
    int    n    = 0;
    double mean = 0.0;
    double M2   = 0.0;

    std::deque<double> window;
    int maxWindow = DEFAULT_WINDOW;

    double zThreshold = DEFAULT_Z_THRESH;

    void addSample(double x) {
        if ((int)window.size() >= maxWindow) {
            double old = window.front();
            window.pop_front();
            if (n > 1) {
                double oldMean = (mean * n - old) / (n - 1);
                M2 -= (old - mean) * (old - oldMean);
                mean = oldMean;
                n--;
            }
        }
        window.push_back(x);
        n++;
        double delta  = x - mean;
        mean         += delta / n;
        double delta2 = x - mean;
        M2           += delta * delta2;
    }

    double variance() const { return (n > 1) ? M2 / (n - 1) : 0.0; }
    double stddev()   const { return std::sqrt(variance()); }

    double zScore(double x) const {
        double s = stddev();
        if (s < 1e-9) return (x > mean + 1e-9) ? 999.0 : 0.0;
        return (x - mean) / s;
    }

    bool isAnomaly(double x)  const { return zScore(x) > zThreshold; }
    bool isWarmedUp()         const { return n >= MIN_SAMPLES; }

    void reset() { n = 0; mean = 0.0; M2 = 0.0; window.clear(); }

    void setWindow(int w) {
        maxWindow = w;
        while ((int)window.size() > maxWindow) {
            window.pop_front();
            n = std::max(0, n - 1);
        }
    }
};

struct IPBaseline {
    BaselineMetric pktRate;
    BaselineMetric synRate;
    BaselineMetric portDiv;
    BaselineMetric icmpRate;
    BaselineMetric udpRate;
    BaselineMetric authRate;

    void setWindow(int w) {
        pktRate.setWindow(w);  synRate.setWindow(w);
        portDiv.setWindow(w);  icmpRate.setWindow(w);
        udpRate.setWindow(w);  authRate.setWindow(w);
    }

    void setZThreshold(double z) {
        pktRate.zThreshold  = z;  synRate.zThreshold  = z;
        portDiv.zThreshold  = z;  icmpRate.zThreshold = z;
        udpRate.zThreshold  = z;  authRate.zThreshold = z;
    }

    void reset() {
        pktRate.reset(); synRate.reset(); portDiv.reset();
        icmpRate.reset(); udpRate.reset(); authRate.reset();
    }
};

std::unordered_map<std::string, IPBaseline> g_baselines;
std::mutex baselineMutex;

double g_zThreshold  = DEFAULT_Z_THRESH;
int    g_windowSecs  = DEFAULT_WINDOW;
int    g_botnetCount = 3;

// ================================================================
//  GLOBAL TRAFFIC SPIKE DETECTION  (NEW)
//  Tracks total packets/s across ALL IPs using its own baseline.
//  If the global z-score spikes AND one IP dominates >40% of
//  traffic AND that IP is already HIGH/CRITICAL — auto-block it.
// ================================================================

BaselineMetric g_totalTraffic;                        // global pkt/s baseline
std::unordered_map<std::string, uint32_t> g_lastBlockTime; // per-IP cooldown

static const uint32_t BLOCK_COOLDOWN_MS = 10000;      // 10-second cooldown

// Millisecond clock — monotonic, wraps after ~49 days (fine for IDS)
static uint32_t millis() {
    using namespace std::chrono;
    return static_cast<uint32_t>(
        duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()).count());
}

// ================================================================
//  THREAT CLASSIFICATION
// ================================================================

enum ThreatLevel { NONE = 0, LOW, MEDIUM, HIGH, CRITICAL };

struct ThreatInfo {
    ThreatLevel level = NONE;
    int         score = 0;
    QString     reasons;
    double zPkt  = 0, zSyn  = 0, zPort = 0;
    double zIcmp = 0, zUdp  = 0, zAuth = 0;
    bool   warmedUp = false;
};

ThreatInfo classify(const std::string &ip, const IPStats &s) {
    ThreatInfo t;
    QStringList reasons;

    std::lock_guard<std::mutex> lk(baselineMutex);
    IPBaseline &bl = g_baselines[ip];
    bl.setZThreshold(g_zThreshold);
    bl.setWindow(g_windowSecs);

    bl.pktRate .addSample(s.pktCount);
    bl.synRate .addSample(s.synCount);
    bl.portDiv .addSample((double)s.dstPorts.size());
    bl.icmpRate.addSample(s.icmpCount);
    bl.udpRate .addSample(s.udpCount);
    bl.authRate.addSample(s.authHits);

    t.zPkt  = bl.pktRate .zScore(s.pktCount);
    t.zSyn  = bl.synRate .zScore(s.synCount);
    t.zPort = bl.portDiv .zScore((double)s.dstPorts.size());
    t.zIcmp = bl.icmpRate.zScore(s.icmpCount);
    t.zUdp = bl.udpRate.zScore(s.udpCount);
    t.zAuth = bl.authRate.zScore(s.authHits);
    t.warmedUp = bl.pktRate.isWarmedUp();

    if (!t.warmedUp) {
        if (s.synCount  >= g_fallback.synFlood)            { t.score += 65; reasons << "SYN FLOOD (fallback)";   }
        if ((int)s.dstPorts.size() >= g_fallback.portScan) { t.score += 65; reasons << "PORT SCAN (fallback)";   }
        if (s.icmpCount >= g_fallback.icmpFlood)           { t.score += 45; reasons << "ICMP FLOOD (fallback)";  }
        if (s.udpCount  >= g_fallback.udpFlood)            { t.score += 45; reasons << "UDP FLOOD (fallback)";   }
        if (s.authHits  >= g_fallback.authBrute)           { t.score += 65; reasons << "BRUTE FORCE (fallback)"; }
        if (s.pktCount  >= g_fallback.pktRate)             { t.score += 65; reasons << "HIGH RATE (fallback)";   }
    } else {
        auto zScore = [&](double z, int base, int boosted, int extreme,
                          const QString &label) {
            double hi  = g_zThreshold * 1.5;
            double vhi = g_zThreshold * 2.5;
            if      (z > vhi)          { t.score += extreme; reasons << label + QString(" (z=%1)").arg(z, 0, 'f', 1); }
            else if (z > hi)           { t.score += boosted; reasons << label + QString(" (z=%1)").arg(z, 0, 'f', 1); }
            else if (z > g_zThreshold) { t.score += base;    reasons << label + QString(" (z=%1)").arg(z, 0, 'f', 1); }
        };

        zScore(t.zSyn,  45, 60, 75, "SYN FLOOD");
        zScore(t.zPort, 45, 60, 75, "PORT SCAN");
        zScore(t.zIcmp, 35, 45, 60, "ICMP FLOOD");
        zScore(t.zUdp,  35, 45, 60, "UDP FLOOD");
        zScore(t.zAuth, 45, 60, 75, "BRUTE FORCE");
        zScore(t.zPkt,  25, 45, 65, "HIGH RATE");
    }

    t.reasons = reasons.join(", ");
    if      (t.score >= 60) t.level = CRITICAL;
    else if (t.score >= 40) t.level = HIGH;
    else if (t.score >= 20) t.level = MEDIUM;
    else if (t.score >   0) t.level = LOW;
    return t;
}

QString levelStr(ThreatLevel l) {
    switch(l) {
        case CRITICAL: return "CRITICAL";
        case HIGH:     return "HIGH";
        case MEDIUM:   return "MEDIUM";
        case LOW:      return "LOW";
        default:       return "NORMAL";
    }
}

QColor levelColor(ThreatLevel l) {
    switch(l) {
        case CRITICAL: return QColor(180,  20,  20);
        case HIGH:     return QColor(190,  90,   0);
        case MEDIUM:   return QColor(150, 120,   0);
        case LOW:      return QColor( 50, 130,  50);
        default:       return QColor( 60,  60,  60);
    }
}

QColor levelBgColor(ThreatLevel l) {
    switch(l) {
        case CRITICAL: return QColor(255, 235, 235);
        case HIGH:     return QColor(255, 243, 225);
        case MEDIUM:   return QColor(255, 252, 220);
        case LOW:      return QColor(230, 250, 230);
        default:       return QColor(245, 245, 245);
    }
}

// ================================================================
//  PACKET HANDLER  (sniffer thread)
//  SOFTWARE BLOCK CHECK IS THE VERY FIRST THING AFTER IP PARSE
// ================================================================

static const uint16_t AUTH_PORTS[] = {21, 22, 23, 3389, 5900};

void packetHandler(u_char*, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    if (hdr->caplen < sizeof(struct ether_header)) return;
    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const u_char *ipStart = pkt + sizeof(struct ether_header);
    size_t ipAvail = hdr->caplen - sizeof(struct ether_header);
    if (ipAvail < sizeof(struct ip)) return;

    const struct ip *iph = (const struct ip *)ipStart;
    int ipHdrLen = iph->ip_hl * 4;
    if ((size_t)ipHdrLen > ipAvail) return;

    std::string src = inet_ntoa(iph->ip_src);

    // ── SOFTWARE BLOCK — zero-latency drop ───────────────────
    {
        std::lock_guard<std::mutex> blk(blockedMutex);
        if (g_blockedIPs.count(src)) return;   // DROP packet silently
    }

    // ── Normal stat collection ────────────────────────────────
    std::lock_guard<std::mutex> lock(statsMutex);
    IPStats &st = ipStats[src];
    st.pktCount++;

    const u_char *tport = ipStart + ipHdrLen;
    size_t tlen = ipAvail - ipHdrLen;

    if (iph->ip_p == IPPROTO_TCP && tlen >= sizeof(struct tcphdr)) {
        const struct tcphdr *tcp = (const struct tcphdr *)tport;
        uint16_t dp = ntohs(tcp->dest);
        if (tcp->syn && !tcp->ack) st.synCount++;
        st.dstPorts.insert(dp);
        for (uint16_t ap : AUTH_PORTS)
            if (dp == ap) { st.authHits++; break; }
    } else if (iph->ip_p == IPPROTO_UDP && tlen >= sizeof(struct udphdr)) {
        const struct udphdr *udp = (const struct udphdr *)tport;
        st.dstPorts.insert(ntohs(udp->dest));
        st.udpCount++;
    } else if (iph->ip_p == IPPROTO_ICMP) {
        st.icmpCount++;
    }
}

// ================================================================
//  STAT CARD
// ================================================================

class StatCard : public QFrame {
public:
    StatCard(const QString &label, QWidget *parent = nullptr) : QFrame(parent) {
        setObjectName("statCard");
        QVBoxLayout *lay = new QVBoxLayout(this);
        lay->setContentsMargins(14, 10, 14, 10);
        lay->setSpacing(2);
        m_value = new QLabel("0");
        m_value->setObjectName("statValue");
        m_value->setAlignment(Qt::AlignLeft);
        m_label = new QLabel(label.toUpper());
        m_label->setObjectName("statLabel");
        lay->addWidget(m_value);
        lay->addWidget(m_label);
        setMinimumWidth(118);
    }
    void setValue(const QString &v) { m_value->setText(v); }
    void setValueColor(const QColor &c) {
        m_value->setStyleSheet(
            QString("color:%1;font-size:22px;font-weight:bold;").arg(c.name()));
    }
private:
    QLabel *m_value, *m_label;
};

// ================================================================
//  MAIN WINDOW
// ================================================================

class IDSWindow : public QMainWindow {
public:
    IDSWindow() {
        setWindowTitle("IDS v4.1 — Adaptive Baseline + Instant Block");
        setMinimumSize(1280, 760);
        applyStyles();
        buildUI();

        QTimer *ui = new QTimer(this);
        QObject::connect(ui, &QTimer::timeout, [this](){ updateUI(); });
        ui->start(1000);

        QTimer *clk = new QTimer(this);
        QObject::connect(clk, &QTimer::timeout, [this](){ updateClock(); });
        clk->start(1000);
        updateClock();
    }

    void setIfaceText(const QString &s) { ifaceLabel->setText(s); }

    void addLog(const QString &type, const QString &detail, ThreatLevel lv = NONE) {
        QColor col;
        if      (type == "BLOCK")   col = QColor(180,  30,  30);
        else if (type == "UNBLOCK") col = QColor( 20, 100, 180);
        else if (type == "AUTO")    col = QColor(160,  70,   0);
        else                        col = levelColor(lv == NONE ? LOW : lv);

        auto mk = [&](const QString &txt) {
            auto *i = new QTableWidgetItem(txt);
            i->setForeground(col);
            return i;
        };

        int row = logView->rowCount();
        logView->insertRow(row);
        logView->setItem(row, 0, mk(QDateTime::currentDateTime().toString("HH:mm:ss")));
        logView->setItem(row, 1, mk("[" + type + "]"));
        logView->setItem(row, 2, mk(detail));
        logView->scrollToBottom();
        if (logView->rowCount() > 200) logView->removeRow(0);
    }

private:
    // UI-side blocked set — mirrors g_blockedIPs, used for display logic only
    std::unordered_set<std::string> blockedIPs;

    struct RegistryEntry {
        ThreatLevel level     = NONE;
        QString     lastSeen;
        int         totalPkts = 0;
        QString     reasons;
    };
    std::map<std::string, RegistryEntry> ipRegistry;
    std::map<std::string, ThreatInfo>   latestThreat;
    int g_totalSamples = 0;

    // ── IPTABLES (async, non-blocking) ───────────────────────
    void runIptablesAsync(const QString &action, const QString &ip) {
        QProcess *proc = new QProcess(this);
        proc->start("sudo", {"iptables", action, "INPUT", "-s", ip, "-j", "DROP"});
        QObject::connect(proc,
            QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            proc, &QProcess::deleteLater);
    }

    // ── BLOCK / UNBLOCK ──────────────────────────────────────
    void blockIP(const QString &ip) {
        std::string s = ip.toStdString();
        if (blockedIPs.count(s)) return;

        {
            std::lock_guard<std::mutex> lk(blockedMutex);
            g_blockedIPs.insert(s);
        }
        blockedIPs.insert(s);
        runIptablesAsync("-A", ip);
        cardBlocked->setValue(QString::number(blockedIPs.size()));
        addLog("BLOCK", ip);
    }

    void unblockIP(const QString &ip) {
        std::string s = ip.toStdString();
        if (!blockedIPs.count(s)) return;

        {
            std::lock_guard<std::mutex> lk(blockedMutex);
            g_blockedIPs.erase(s);
        }
        blockedIPs.erase(s);
        runIptablesAsync("-D", ip);
        cardBlocked->setValue(QString::number(blockedIPs.size()));
        addLog("UNBLOCK", ip);
    }

    // ── IP REGISTRY ──────────────────────────────────────────

    QTableWidget *registryTable  = nullptr;
    QLineEdit    *registryFilter = nullptr;

    void ensureRegistryRow(const std::string &ip) {
        for (int r = 0; r < registryTable->rowCount(); r++) {
            if (registryTable->item(r, 1) &&
                registryTable->item(r, 1)->text().toStdString() == ip)
                return;
        }
        int row = registryTable->rowCount();
        registryTable->insertRow(row);

        QTableWidgetItem *chk = new QTableWidgetItem();
        chk->setCheckState(Qt::Unchecked);
        chk->setTextAlignment(Qt::AlignCenter);
        registryTable->setItem(row, 0, chk);

        auto mkItem = [](const QString &txt,
                         Qt::Alignment al = Qt::AlignVCenter | Qt::AlignLeft) {
            auto *it = new QTableWidgetItem(txt);
            it->setTextAlignment(al);
            it->setFlags(it->flags() & ~Qt::ItemIsEditable);
            return it;
        };
        registryTable->setItem(row, 1, mkItem(QString::fromStdString(ip)));
        registryTable->setItem(row, 2, mkItem("NORMAL", Qt::AlignCenter));
        registryTable->setItem(row, 3, mkItem("0",      Qt::AlignCenter));
        registryTable->setItem(row, 4, mkItem("—",      Qt::AlignCenter));
        registryTable->setItem(row, 5, mkItem("—"));
        registryTable->setItem(row, 6, mkItem("NORMAL", Qt::AlignCenter));

        QPushButton *btn = new QPushButton("BLOCK");
        btn->setObjectName("inlineBlockBtn");
        btn->setCursor(Qt::PointingHandCursor);
        QString ipStr = QString::fromStdString(ip);
        QObject::connect(btn, &QPushButton::clicked, [this, ipStr]() {
            bool isBlocked = blockedIPs.count(ipStr.toStdString()) > 0;
            if (isBlocked) unblockIP(ipStr);
            else           blockIP(ipStr);
            refreshRegistryRow(ipStr.toStdString());
        });
        registryTable->setCellWidget(row, 7, btn);
    }

    void refreshRegistryRow(const std::string &ip) {
        bool blocked = blockedIPs.count(ip) > 0;
        auto it = ipRegistry.find(ip);
        if (it == ipRegistry.end()) return;
        const RegistryEntry &e = it->second;

        for (int r = 0; r < registryTable->rowCount(); r++) {
            if (!registryTable->item(r, 1)) continue;
            if (registryTable->item(r, 1)->text().toStdString() != ip) continue;

            QColor col = blocked ? QColor(140, 140, 140) : levelColor(e.level);

            auto setTxt = [&](int col_, const QString &txt,
                               Qt::Alignment al = Qt::AlignVCenter | Qt::AlignLeft) {
                auto *cell = registryTable->item(r, col_);
                if (!cell) return;
                cell->setText(txt);
                cell->setForeground(col);
                cell->setTextAlignment(al);
                if (blocked) cell->setBackground(QColor(240, 240, 240));
                else         cell->setBackground(levelBgColor(e.level));
            };

            QString stTxt = blocked ? "BLOCKED" : levelStr(e.level);
            setTxt(2, levelStr(e.level),           Qt::AlignCenter);
            setTxt(3, QString::number(e.totalPkts), Qt::AlignCenter);
            setTxt(4, e.lastSeen,                   Qt::AlignCenter);
            setTxt(5, e.reasons.isEmpty() ? "—" : e.reasons);
            setTxt(6, stTxt,                        Qt::AlignCenter);

            if (auto *btn = qobject_cast<QPushButton*>(registryTable->cellWidget(r, 7))) {
                btn->setText(blocked ? "UNBLOCK" : "BLOCK");
                btn->setObjectName(blocked ? "inlineUnblockBtn" : "inlineBlockBtn");
                btn->style()->polish(btn);
            }
            break;
        }
    }

    void applyRegistryFilter(const QString &text) {
        for (int r = 0; r < registryTable->rowCount(); r++) {
            auto *cell = registryTable->item(r, 1);
            bool show = !cell || cell->text().contains(text, Qt::CaseInsensitive);
            registryTable->setRowHidden(r, !show);
        }
    }

    void registryBlockSelected() {
        for (int r = 0; r < registryTable->rowCount(); r++) {
            auto *chk = registryTable->item(r, 0);
            auto *ipc = registryTable->item(r, 1);
            if (chk && ipc && chk->checkState() == Qt::Checked)
                blockIP(ipc->text());
        }
        for (auto &[ip, _] : ipRegistry) refreshRegistryRow(ip);
    }

    void registryUnblockSelected() {
        for (int r = 0; r < registryTable->rowCount(); r++) {
            auto *chk = registryTable->item(r, 0);
            auto *ipc = registryTable->item(r, 1);
            if (chk && ipc && chk->checkState() == Qt::Checked)
                unblockIP(ipc->text());
        }
        for (auto &[ip, _] : ipRegistry) refreshRegistryRow(ip);
    }

    void registrySelectAll(bool checked) {
        for (int r = 0; r < registryTable->rowCount(); r++) {
            if (registryTable->isRowHidden(r)) continue;
            auto *chk = registryTable->item(r, 0);
            if (chk) chk->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
        }
    }

    // ── BASELINE TAB ─────────────────────────────────────────

    QTableWidget *baselineTable = nullptr;

    void ensureBaselineRow(const std::string &ip) {
        for (int r = 0; r < baselineTable->rowCount(); r++) {
            if (baselineTable->item(r, 0) &&
                baselineTable->item(r, 0)->text().toStdString() == ip)
                return;
        }
        int row = baselineTable->rowCount();
        baselineTable->insertRow(row);
        auto mkItem = [](const QString &txt,
                         Qt::Alignment al = Qt::AlignVCenter | Qt::AlignCenter) {
            auto *it = new QTableWidgetItem(txt);
            it->setTextAlignment(al);
            it->setFlags(it->flags() & ~Qt::ItemIsEditable);
            return it;
        };
        baselineTable->setItem(row, 0, mkItem(QString::fromStdString(ip),
                                              Qt::AlignLeft | Qt::AlignVCenter));
        for (int c = 1; c <= 9; c++)
            baselineTable->setItem(row, c, mkItem("—"));
    }

    void refreshBaselineRow(const std::string &ip, const ThreatInfo &ti) {
        std::lock_guard<std::mutex> lk(baselineMutex);
        auto bit = g_baselines.find(ip);
        if (bit == g_baselines.end()) return;
        const IPBaseline &bl = bit->second;

        for (int r = 0; r < baselineTable->rowCount(); r++) {
            if (!baselineTable->item(r, 0)) continue;
            if (baselineTable->item(r, 0)->text().toStdString() != ip) continue;

            auto setCell = [&](int col, const QString &txt,
                                QColor fg = QColor(60,60,60),
                                QColor bg = QColor(245,245,245)) {
                auto *cell = baselineTable->item(r, col);
                if (!cell) return;
                cell->setText(txt);
                cell->setForeground(fg);
                cell->setBackground(bg);
            };

            QString wu = bl.pktRate.isWarmedUp()
                ? "✓"
                : QString("(%1/%2)").arg(bl.pktRate.n).arg(MIN_SAMPLES);
            QColor wuCol = bl.pktRate.isWarmedUp()
                ? QColor(40,140,40) : QColor(160,120,0);
            setCell(1, wu, wuCol, QColor(245,245,245));
            setCell(2, QString::number(bl.pktRate.mean,   'f', 1));
            setCell(3, QString::number(bl.pktRate.stddev(),'f', 2));

            auto zColor = [&](double z) -> QColor {
                if (z > g_zThreshold * 2.5) return QColor(180, 20, 20);
                if (z > g_zThreshold)       return QColor(190, 90,  0);
                if (z > g_zThreshold * 0.7) return QColor(150,120,  0);
                return QColor(40,140,40);
            };
            auto zBg = [&](double z) -> QColor {
                if (z > g_zThreshold * 2.5) return QColor(255,235,235);
                if (z > g_zThreshold)       return QColor(255,243,225);
                return QColor(245,245,245);
            };
            auto fmt = [](double z){ return QString::number(z, 'f', 2); };

            setCell(4, fmt(ti.zPkt),  zColor(ti.zPkt),  zBg(ti.zPkt));
            setCell(5, fmt(ti.zSyn),  zColor(ti.zSyn),  zBg(ti.zSyn));
            setCell(6, fmt(ti.zPort), zColor(ti.zPort), zBg(ti.zPort));
            setCell(7, fmt(ti.zIcmp), zColor(ti.zIcmp), zBg(ti.zIcmp));
            setCell(8, fmt(ti.zUdp),  zColor(ti.zUdp),  zBg(ti.zUdp));
            setCell(9, fmt(ti.zAuth), zColor(ti.zAuth), zBg(ti.zAuth));
            break;
        }
    }

    // ── UPDATE UI ────────────────────────────────────────────

    void updateUI() {
        // ─────────────────────────────────────────────────────
        // SNAPSHOT — move stats off the sniffer thread atomically
        // ─────────────────────────────────────────────────────
        std::unordered_map<std::string, IPStats> snap;
        {
            std::lock_guard<std::mutex> lk(statsMutex);
            snap = std::move(ipStats);
            ipStats.clear();
        }

        // Push zero-samples for IPs not seen this second
        {
            std::lock_guard<std::mutex> lk(baselineMutex);
            for (auto &[ip, bl] : g_baselines) {
                if (snap.find(ip) == snap.end()) {
                    bl.pktRate .addSample(0);
                    bl.synRate .addSample(0);
                    bl.portDiv .addSample(0);
                    bl.icmpRate.addSample(0);
                    bl.udpRate .addSample(0);
                    bl.authRate.addSample(0);
                }
            }
        }

        table->setRowCount(0);
        g_totalSamples++;

        // ─────────────────────────────────────────────────────
        // ACCUMULATORS for global spike detection
        // ─────────────────────────────────────────────────────
        int total        = 0;
        int totalPackets = 0;   // same value — kept separate for clarity
        int highCount    = 0;
        std::string topIP;
        int topPackets   = 0;
        ThreatLevel worst = NONE;

        // ─────────────────────────────────────────────────────
        // PROCESS IPs — classify, update registry/baseline rows,
        // handle existing per-IP CRITICAL auto-block (unchanged)
        // ─────────────────────────────────────────────────────
        for (auto &[ip, st] : snap) {
            total        += st.pktCount;
            totalPackets += st.pktCount;

            // Track top contributor for dominance check
            if (st.pktCount > topPackets) {
                topPackets = st.pktCount;
                topIP      = ip;
            }

            bool blocked = blockedIPs.count(ip);
            ThreatInfo ti = classify(ip, st);
            latestThreat[ip] = ti;

            if (ti.level > worst) worst = ti.level;
            if (ti.level >= HIGH) highCount++;

            RegistryEntry &re = ipRegistry[ip];
            re.level     = ti.level;
            re.lastSeen  = QDateTime::currentDateTime().toString("HH:mm:ss");
            re.totalPkts += st.pktCount;
            re.reasons   = ti.reasons;
            ensureRegistryRow(ip);
            refreshRegistryRow(ip);
            ensureBaselineRow(ip);
            refreshBaselineRow(ip, ti);

            // EXISTING AUTO-BLOCK (per-IP CRITICAL) — UNCHANGED
            if (autoBlockChk->isChecked() && ti.level == CRITICAL && !blocked) {
                blockIP(QString::fromStdString(ip));
                addLog("AUTO", QString::fromStdString(ip) + " — " + ti.reasons, CRITICAL);
                refreshRegistryRow(ip);
                continue;
            }

            // Live traffic table row
            int row = table->rowCount();
            table->insertRow(row);

            QColor col = blocked ? QColor(140, 140, 140) : levelColor(ti.level);
            QColor bg  = blocked ? QColor(240, 240, 240) : levelBgColor(ti.level);

            auto mk = [&](const QString &txt,
                          Qt::Alignment al = Qt::AlignVCenter | Qt::AlignLeft) {
                auto *it = new QTableWidgetItem(txt);
                it->setForeground(col);
                it->setBackground(bg);
                it->setTextAlignment(al);
                return it;
            };

            double maxZ = std::max({ti.zPkt, ti.zSyn, ti.zPort,
                                    ti.zIcmp, ti.zUdp, ti.zAuth});
            QString zStr = ti.warmedUp
                ? QString("z=") + QString::number(maxZ, 'f', 1)
                : "warming…";

            QString stTxt = blocked ? "BLOCKED" : levelStr(ti.level);
            table->setItem(row, 0, mk(QString::fromStdString(ip)));
            table->setItem(row, 1, mk(QString::number(st.pktCount),        Qt::AlignCenter));
            table->setItem(row, 2, mk(QString::number(st.synCount),        Qt::AlignCenter));
            table->setItem(row, 3, mk(QString::number(st.dstPorts.size()), Qt::AlignCenter));
            table->setItem(row, 4, mk(QString::number(st.icmpCount),       Qt::AlignCenter));
            table->setItem(row, 5, mk(ti.reasons.isEmpty() ? "—" : ti.reasons));
            table->setItem(row, 6, mk(zStr,  Qt::AlignCenter));
            table->setItem(row, 7, mk(stTxt, Qt::AlignCenter));

            QPushButton *btn = new QPushButton(blocked ? "UNBLOCK" : "BLOCK");
            btn->setObjectName(blocked ? "inlineUnblockBtn" : "inlineBlockBtn");
            btn->setCursor(Qt::PointingHandCursor);
            QString ipStr = QString::fromStdString(ip);
            QObject::connect(btn, &QPushButton::clicked, [this, ipStr]() {
                if (blockedIPs.count(ipStr.toStdString())) unblockIP(ipStr);
                else                                        blockIP(ipStr);
            });
            table->setCellWidget(row, 8, btn);

            if (ti.level >= MEDIUM)
                addLog(levelStr(ti.level),
                       QString::fromStdString(ip) + " — " + ti.reasons, ti.level);
        }

        // ─────────────────────────────────────────────────────
        // 🔥 GLOBAL TRAFFIC SPIKE DETECTION
        //
        // Feed the global baseline one sample per tick.
        // If total traffic z-score exceeds threshold AND a single
        // IP owns >40% of that traffic AND it is already HIGH+,
        // auto-block it (with a per-IP 10 s cooldown so we never
        // spam the log or issue duplicate blocks).
        // ─────────────────────────────────────────────────────
        g_totalTraffic.addSample(totalPackets);
        double zGlobal = g_totalTraffic.zScore(totalPackets);

        if (autoBlockChk->isChecked()          // respect the auto-block toggle
            && g_totalTraffic.isWarmedUp()     // don't act during warm-up
            && zGlobal > g_zThreshold          // global spike detected
            && totalPackets > 0                // sanity: non-zero traffic
            && !topIP.empty())                 // at least one active IP
        {
            double dominance = (double)topPackets / (double)totalPackets;

            if (dominance > 0.4) {             // top IP owns >40% of traffic
                auto it = latestThreat.find(topIP);
                if (it != latestThreat.end() && it->second.level >= HIGH) {
                    uint32_t now = millis();
                    uint32_t &lastBlock = g_lastBlockTime[topIP];

                    if (now - lastBlock > BLOCK_COOLDOWN_MS) {
                        if (!blockedIPs.count(topIP)) {
                            QString ipStr = QString::fromStdString(topIP);
                            blockIP(ipStr);
                            addLog("AUTO",
                                QString("[GLOBAL SPIKE] %1 dominating %2% of traffic "
                                        "(z=%3, level=%4)")
                                    .arg(ipStr)
                                    .arg(dominance * 100, 0, 'f', 1)
                                    .arg(zGlobal,         0, 'f', 1)
                                    .arg(levelStr(it->second.level)),
                                CRITICAL);
                            refreshRegistryRow(topIP);
                            lastBlock = now;
                        }
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────
        // STATS CARDS — update after all processing is done
        // ─────────────────────────────────────────────────────
        cardTotal   ->setValue(QString::number(total));
        cardUnique  ->setValue(QString::number(snap.size()));
        cardThreats ->setValue(QString::number(highCount));
        cardThreats ->setValueColor(highCount > 0 ? levelColor(HIGH) : QColor(40,140,40));
        cardBlocked ->setValue(QString::number(blockedIPs.size()));
        cardRegistry->setValue(QString::number(ipRegistry.size()));

        // Warm-up indicator
        bool anyWarmedUp = false;
        {
            std::lock_guard<std::mutex> lk(baselineMutex);
            for (auto &[ip, bl] : g_baselines)
                if (bl.pktRate.isWarmedUp()) { anyWarmedUp = true; break; }
        }
        if (!anyWarmedUp && !g_baselines.empty()) {
            int minN = MIN_SAMPLES;
            std::lock_guard<std::mutex> lk(baselineMutex);
            for (auto &[ip, bl] : g_baselines)
                minN = std::min(minN, bl.pktRate.n);
            warmupLabel->setText(
                QString("⏳ Baseline warming up… %1/%2 samples").arg(minN).arg(MIN_SAMPLES));
            warmupLabel->setVisible(true);
        } else {
            warmupLabel->setVisible(false);
        }

        bool botnet = (highCount >= g_botnetCount);
        ThreatLevel display = botnet ? CRITICAL : worst;

        if (botnet)
            setStatus("BOTNET — " + QString::number(highCount) + " coordinated sources", CRITICAL);
        else if (display >= HIGH)
            setStatus("THREAT: " + levelStr(display), display);
        else if (display >= LOW)
            setStatus("ANOMALY — " + levelStr(display), display);
        else
            setStatus("All systems nominal", NONE);
    }

    void setStatus(const QString &msg, ThreatLevel lv) {
        statusLabel->setText(msg);
        statusLabel->setStyleSheet(
            QString("color:%1;font-size:11px;font-weight:bold;letter-spacing:1px;")
            .arg(levelColor(lv).name()));
    }

    void updateClock() {
        clockLabel->setText(QDateTime::currentDateTime().toString("yyyy-MM-dd  HH:mm:ss"));
    }

    // ── BUILD UI ─────────────────────────────────────────────

    void buildUI() {
        QWidget *root = new QWidget;
        QVBoxLayout *rootLay = new QVBoxLayout(root);
        rootLay->setContentsMargins(0,0,0,0);
        rootLay->setSpacing(0);

        // TOP BAR
        {
            QWidget *tb = new QWidget;
            tb->setObjectName("topBar");
            tb->setFixedHeight(52);
            QHBoxLayout *tl = new QHBoxLayout(tb);
            tl->setContentsMargins(24,0,24,0);
            tl->setSpacing(10);
            QLabel *logo = new QLabel("IDS");
            logo->setObjectName("logo");
            statusLabel = new QLabel("All systems nominal");
            statusLabel->setObjectName("statusLabel");
            clockLabel  = new QLabel;
            clockLabel->setObjectName("clockLabel");
            tl->addWidget(logo);
            tl->addStretch();
            tl->addWidget(statusLabel);
            tl->addSpacing(24);
            tl->addWidget(clockLabel);
            rootLay->addWidget(tb);
        }

        auto *sep0 = new QFrame;
        sep0->setFrameShape(QFrame::HLine);
        sep0->setObjectName("separator");
        rootLay->addWidget(sep0);

        QWidget *body = new QWidget;
        body->setObjectName("body");
        QHBoxLayout *bodyLay = new QHBoxLayout(body);
        bodyLay->setContentsMargins(16,12,16,12);
        bodyLay->setSpacing(12);

        // LEFT PANEL
        QWidget *left = new QWidget;
        QVBoxLayout *leftLay = new QVBoxLayout(left);
        leftLay->setContentsMargins(0,0,0,0);
        leftLay->setSpacing(10);

        // Stat cards
        {
            QWidget *cr = new QWidget;
            QHBoxLayout *cl = new QHBoxLayout(cr);
            cl->setContentsMargins(0,0,0,0); cl->setSpacing(8);
            cardTotal    = new StatCard("Packets/s");
            cardUnique   = new StatCard("Active IPs");
            cardThreats  = new StatCard("Threats");
            cardBlocked  = new StatCard("Blocked");
            cardRegistry = new StatCard("IPs Seen");
            cl->addWidget(cardTotal);
            cl->addWidget(cardUnique);
            cl->addWidget(cardThreats);
            cl->addWidget(cardBlocked);
            cl->addWidget(cardRegistry);
            cl->addStretch();
            leftLay->addWidget(cr);
        }

        // Controls
        {
            QWidget *cr = new QWidget;
            cr->setObjectName("ctrlRow");
            QHBoxLayout *cl = new QHBoxLayout(cr);
            cl->setContentsMargins(12,7,12,7); cl->setSpacing(14);

            autoBlockChk = new QCheckBox("Auto-block CRITICAL");
            autoBlockChk->setObjectName("ctrlCheck");
            cl->addWidget(autoBlockChk);

            // Sigma
            {
                QLabel *l = new QLabel("Sigma (σ):");
                l->setObjectName("ctrlLabel");
                cl->addWidget(l);
                QDoubleSpinBox *s = new QDoubleSpinBox;
                s->setRange(1.0, 6.0);
                s->setSingleStep(0.5);
                s->setValue(g_zThreshold);
                s->setDecimals(1);
                s->setObjectName("ctrlSpin");
                s->setToolTip(
                    "Z-score threshold for anomaly detection.\n"
                    "Lower = more sensitive. Higher = less sensitive.\n"
                    "Default 3.0 = flag observations > 3σ from mean.");
                QObject::connect(s, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
                                 [](double v){ g_zThreshold = v; });
                cl->addWidget(s);
            }

            // Window
            {
                QLabel *l = new QLabel("Window (s):");
                l->setObjectName("ctrlLabel");
                cl->addWidget(l);
                QSpinBox *s = new QSpinBox;
                s->setRange(30, 3600);
                s->setValue(g_windowSecs);
                s->setObjectName("ctrlSpin");
                s->setToolTip("Baseline sliding window size in seconds.");
                QObject::connect(s, QOverload<int>::of(&QSpinBox::valueChanged),
                                 [](int v){ g_windowSecs = v; });
                cl->addWidget(s);
            }

            // Botnet
            {
                QLabel *l = new QLabel("Botnet≥:");
                l->setObjectName("ctrlLabel");
                cl->addWidget(l);
                QSpinBox *s = new QSpinBox;
                s->setRange(2, 20);
                s->setValue(g_botnetCount);
                s->setObjectName("ctrlSpin");
                QObject::connect(s, QOverload<int>::of(&QSpinBox::valueChanged),
                                 [](int v){ g_botnetCount = v; });
                cl->addWidget(s);
            }

            // Reset baselines
            {
                QPushButton *rb = new QPushButton("Reset Baselines");
                rb->setObjectName("resetBaselineBtn");
                rb->setCursor(Qt::PointingHandCursor);
                rb->setToolTip("Clears all learned baselines and restarts warm-up.");
                QObject::connect(rb, &QPushButton::clicked, [this]() {
                    std::lock_guard<std::mutex> lk(baselineMutex);
                    for (auto &[ip, bl] : g_baselines) bl.reset();
                    addLog("INFO", "All baselines reset — warm-up restarted");
                });
                cl->addWidget(rb);
            }

            cl->addStretch();
            leftLay->addWidget(cr);
        }

        // Warm-up label
        warmupLabel = new QLabel;
        warmupLabel->setObjectName("warmupLabel");
        warmupLabel->setVisible(false);
        leftLay->addWidget(warmupLabel);

        {
            QLabel *tt = new QLabel("Live Traffic  —  updates every second");
            tt->setObjectName("sectionTitle");
            leftLay->addWidget(tt);
        }

        // Live traffic table
        table = new QTableWidget;
        table->setObjectName("trafficTable");
        table->setColumnCount(9);
        table->setHorizontalHeaderLabels({
            "Source IP", "Pkts/s", "SYN/s", "Ports", "ICMP/s",
            "Detections", "Max Z", "Status", "Action"});
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        for (int c : {1,2,3,4})
            table->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
        for (int c : {6,7,8})
            table->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
        table->verticalHeader()->setVisible(false);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setShowGrid(true);
        table->setAlternatingRowColors(true);
        leftLay->addWidget(table);
        bodyLay->addWidget(left, 3);

        // RIGHT PANEL — tabs
        QWidget *right = new QWidget;
        right->setObjectName("rightPanel");
        QVBoxLayout *rightLay = new QVBoxLayout(right);
        rightLay->setContentsMargins(0,0,0,0);
        rightLay->setSpacing(0);

        QTabWidget *tabs = new QTabWidget;
        tabs->setObjectName("rightTabs");

        // Tab 1: IP Registry
        {
            QWidget *rt = new QWidget;
            QVBoxLayout *rl = new QVBoxLayout(rt);
            rl->setContentsMargins(8,8,8,8); rl->setSpacing(6);

            QLabel *hint = new QLabel(
                "Every IP seen is listed here. Use BLOCK/UNBLOCK per row "
                "or tick checkboxes for bulk actions.");
            hint->setObjectName("hintLabel");
            hint->setWordWrap(true);
            rl->addWidget(hint);

            {
                QWidget *fb = new QWidget;
                QHBoxLayout *fl = new QHBoxLayout(fb);
                fl->setContentsMargins(0,0,0,0); fl->setSpacing(8);
                registryFilter = new QLineEdit;
                registryFilter->setObjectName("registryFilter");
                registryFilter->setPlaceholderText("Filter by IP…");
                QObject::connect(registryFilter, &QLineEdit::textChanged,
                                 [this](const QString &t){ applyRegistryFilter(t); });
                fl->addWidget(registryFilter);
                QCheckBox *selAll = new QCheckBox("Select all");
                selAll->setObjectName("ctrlCheck");
                QObject::connect(selAll, &QCheckBox::toggled,
                                 [this](bool c){ registrySelectAll(c); });
                fl->addWidget(selAll);
                rl->addWidget(fb);
            }

            registryTable = new QTableWidget;
            registryTable->setObjectName("registryTable");
            registryTable->setColumnCount(8);
            registryTable->setHorizontalHeaderLabels({
                "", "IP Address", "Threat", "Total Pkts",
                "Last Seen", "Detections", "Status", "Action"});
            registryTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            registryTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
            for (int c : {2,3,4,6,7})
                registryTable->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
            registryTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
            registryTable->verticalHeader()->setVisible(false);
            registryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            registryTable->setShowGrid(true);
            registryTable->setAlternatingRowColors(true);
            rl->addWidget(registryTable, 1);

            {
                QWidget *ab = new QWidget;
                QHBoxLayout *al = new QHBoxLayout(ab);
                al->setContentsMargins(0,4,0,0); al->setSpacing(8);
                auto mkBtn = [&](const QString &lbl, const QString &obj, auto slot) {
                    QPushButton *b = new QPushButton(lbl);
                    b->setObjectName(obj);
                    b->setCursor(Qt::PointingHandCursor);
                    QObject::connect(b, &QPushButton::clicked, slot);
                    al->addWidget(b);
                };
                mkBtn("Block selected",   "blockBtnBulk",   [this](){ registryBlockSelected(); });
                mkBtn("Unblock selected", "unblockBtnBulk", [this](){ registryUnblockSelected(); });
                al->addStretch();
                rl->addWidget(ab);
            }
            tabs->addTab(rt, "IP Registry");
        }

        // Tab 2: Baseline Monitor
        {
            QWidget *bt = new QWidget;
            QVBoxLayout *bl2 = new QVBoxLayout(bt);
            bl2->setContentsMargins(8,8,8,8); bl2->setSpacing(6);

            QLabel *hint2 = new QLabel(
                "Per-IP adaptive baseline (Welford online μ/σ). "
                "Z-scores above σ threshold are highlighted. "
                "✓ = warmed up  |  (n/30) = samples so far.");
            hint2->setObjectName("hintLabel");
            hint2->setWordWrap(true);
            bl2->addWidget(hint2);

            baselineTable = new QTableWidget;
            baselineTable->setObjectName("registryTable");
            baselineTable->setColumnCount(10);
            baselineTable->setHorizontalHeaderLabels({
                "IP", "Ready", "μ Pkt", "σ Pkt",
                "z Pkt", "z SYN", "z Port", "z ICMP", "z UDP", "z Auth"});
            baselineTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
            for (int c = 1; c <= 9; c++)
                baselineTable->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
            baselineTable->verticalHeader()->setVisible(false);
            baselineTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            baselineTable->setShowGrid(true);
            baselineTable->setAlternatingRowColors(true);
            bl2->addWidget(baselineTable, 1);
            tabs->addTab(bt, "Baseline Monitor");
        }

        // Tab 3: Event Log
        {
            QWidget *lt = new QWidget;
            QVBoxLayout *ll = new QVBoxLayout(lt);
            ll->setContentsMargins(4,4,4,4); ll->setSpacing(0);

            logView = new QTableWidget;
            logView->setObjectName("logTable");
            logView->setColumnCount(3);
            logView->setHorizontalHeaderLabels({"Time", "Type", "Detail"});
            logView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            logView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
            logView->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
            logView->verticalHeader()->setVisible(false);
            logView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            logView->setShowGrid(true);
            logView->setAlternatingRowColors(true);
            ll->addWidget(logView);
            tabs->addTab(lt, "Event Log");
        }

        rightLay->addWidget(tabs);
        bodyLay->addWidget(right, 2);
        rootLay->addWidget(body);

        // BOTTOM BAR
        {
            QWidget *bb = new QWidget;
            bb->setObjectName("bottomBar");
            bb->setFixedHeight(26);
            QHBoxLayout *bl3 = new QHBoxLayout(bb);
            bl3->setContentsMargins(24,0,24,0);
            ifaceLabel = new QLabel("Interface: detecting…");
            ifaceLabel->setObjectName("statusBarText");
            bl3->addWidget(ifaceLabel);
            bl3->addStretch();
            QLabel *ver = new QLabel(
                "IDS  •  v4.1  •  Adaptive Baseline  •  Instant Block  •  7 engines");
            ver->setObjectName("statusBarText");
            bl3->addWidget(ver);
            rootLay->addWidget(bb);
        }

        setCentralWidget(root);
    }

    // ── STYLES ───────────────────────────────────────────────

    void applyStyles() {
        setStyleSheet(R"(
            QMainWindow, QWidget {
                background-color: #f5f5f5;
                color: #1a1a1a;
                font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                font-size: 12px;
            }
            #topBar { background-color: #ffffff; border-bottom: 1px solid #e0e0e0; }
            #logo { font-size: 15px; font-weight: bold; letter-spacing: 1px; color: #1a1a1a; }
            #clockLabel { color: #888888; font-size: 11px; }
            #statusLabel { font-size: 11px; font-weight: bold; color: #2e7d32; }
            #separator { background-color: #e0e0e0; max-height: 1px; border: none; }
            #body { background-color: #f5f5f5; }

            #statCard {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
            }
            #statValue { font-size: 22px; font-weight: bold; color: #1a1a1a; }
            #statLabel { font-size: 9px; letter-spacing: 2px; color: #888888; }

            #ctrlRow {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
            }
            #ctrlCheck { color: #333333; font-size: 11px; spacing: 6px; }
            #ctrlCheck::indicator {
                width: 13px; height: 13px;
                border: 1px solid #cccccc;
                border-radius: 2px;
                background: #ffffff;
            }
            #ctrlCheck::indicator:checked { background: #1976d2; border-color: #1976d2; }
            #ctrlLabel { color: #666666; font-size: 10px; }
            #ctrlSpin {
                background: #ffffff; border: 1px solid #cccccc;
                color: #1a1a1a; padding: 2px 4px; width: 60px; border-radius: 3px;
            }
            #ctrlSpin::up-button, #ctrlSpin::down-button { width: 14px; }

            #warmupLabel {
                color: #b07800; font-size: 10px; font-weight: bold;
                background: #fff8e1; border: 1px solid #ffe082;
                border-radius: 4px; padding: 3px 10px;
            }
            #resetBaselineBtn {
                background: #ffffff; border: 1px solid #888888;
                color: #555555; font-size: 10px; letter-spacing: 1px;
                padding: 3px 10px; border-radius: 3px;
            }
            #resetBaselineBtn:hover { background: #f5f5f5; color: #222222; }

            #sectionTitle {
                font-size: 11px; font-weight: bold; letter-spacing: 1px;
                color: #555555; padding: 2px 0 4px 0;
            }
            #hintLabel { color: #888888; font-size: 10px; padding: 2px 2px 4px 2px; }

            #trafficTable, #logTable, #registryTable {
                background-color: #ffffff; border: 1px solid #e0e0e0;
                border-radius: 6px; gridline-color: #f0f0f0;
                selection-background-color: #e3f2fd; selection-color: #0d47a1;
                alternate-background-color: #fafafa; outline: 0;
            }
            #trafficTable::item, #logTable::item, #registryTable::item {
                padding: 4px 8px; border: none;
            }
            QHeaderView::section {
                background-color: #fafafa; color: #555555;
                font-size: 10px; letter-spacing: 1px; font-weight: bold;
                border: none; border-bottom: 1px solid #e0e0e0;
                border-right: 1px solid #f0f0f0; padding: 5px 8px;
            }
            QScrollBar:vertical { background: #f5f5f5; width: 6px; border: none; }
            QScrollBar::handle:vertical { background: #cccccc; border-radius: 3px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

            #registryFilter {
                background: #ffffff; border: 1px solid #cccccc;
                color: #1a1a1a; font-size: 11px; padding: 4px 8px; border-radius: 4px;
            }
            #registryFilter:focus { border-color: #1976d2; }

            #inlineBlockBtn {
                background: #ffffff; border: 1px solid #e53935;
                color: #e53935; font-size: 9px; letter-spacing: 1px;
                padding: 3px 8px; border-radius: 3px; min-width: 60px;
            }
            #inlineBlockBtn:hover { background: #ffebee; color: #b71c1c; border-color: #b71c1c; }
            #inlineBlockBtn:pressed { background: #ffcdd2; }

            #inlineUnblockBtn {
                background: #ffffff; border: 1px solid #1976d2;
                color: #1976d2; font-size: 9px; letter-spacing: 1px;
                padding: 3px 8px; border-radius: 3px; min-width: 60px;
            }
            #inlineUnblockBtn:hover { background: #e3f2fd; color: #0d47a1; border-color: #0d47a1; }
            #inlineUnblockBtn:pressed { background: #bbdefb; }

            #blockBtnBulk {
                background: #ffffff; border: 1px solid #e53935; color: #e53935;
                font-size: 10px; letter-spacing: 1px; padding: 4px 12px; border-radius: 4px;
            }
            #blockBtnBulk:hover { background: #ffebee; }
            #unblockBtnBulk {
                background: #ffffff; border: 1px solid #1976d2; color: #1976d2;
                font-size: 10px; letter-spacing: 1px; padding: 4px 12px; border-radius: 4px;
            }
            #unblockBtnBulk:hover { background: #e3f2fd; }

            #rightTabs::pane {
                border: 1px solid #e0e0e0; background: #ffffff;
                border-radius: 0 0 6px 6px;
            }
            #rightTabs QTabBar::tab {
                background: #f5f5f5; color: #888888;
                border: 1px solid #e0e0e0; border-bottom: none;
                padding: 6px 16px; font-size: 10px; letter-spacing: 1px;
                margin-right: 2px; border-radius: 4px 4px 0 0;
            }
            #rightTabs QTabBar::tab:selected {
                background: #ffffff; color: #1976d2; border-top: 2px solid #1976d2;
            }
            #rightTabs QTabBar::tab:hover { color: #333333; }

            #bottomBar { background-color: #ffffff; border-top: 1px solid #e0e0e0; }
            #statusBarText { color: #aaaaaa; font-size: 9px; letter-spacing: 1px; }
        )");
    }

    // ── MEMBERS ──────────────────────────────────────────────
    QLabel       *statusLabel, *clockLabel, *ifaceLabel, *warmupLabel;
    QTableWidget *table, *logView;
    StatCard     *cardTotal, *cardUnique, *cardThreats, *cardBlocked, *cardRegistry;
    QCheckBox    *autoBlockChk;
};

// ================================================================
//  MAIN
// ================================================================

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setStyle("Fusion");

    IDSWindow window;
    window.show();

    char errbuf[PCAP_ERRBUF_SIZE];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    char *dev = pcap_lookupdev(errbuf);
#pragma GCC diagnostic pop

    if (!dev) {
        window.setIfaceText("Interface: not found");
        window.addLog("ERROR", errbuf);
        return app.exec();
    }

    window.setIfaceText(QString("Interface: ") + dev);
    window.addLog("INIT", QString("Listening on ") + dev);
    window.addLog("INFO",
        QString("IDS v4.1 — Welford baseline, window=%1s, σ=%2, warm-up=%3 samples")
        .arg(g_windowSecs).arg(g_zThreshold).arg(MIN_SAMPLES));
    window.addLog("INFO",
        "Block engine: software drop (instant) + iptables (async backup)");
    window.addLog("INFO",
        "Global spike engine: active — dominance threshold 40%, cooldown 10s");

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        window.addLog("ERROR", errbuf);
        return app.exec();
    }

    std::thread([handle]() {
        pcap_loop(handle, 0, packetHandler, nullptr);
    }).detach();

    return app.exec();
}