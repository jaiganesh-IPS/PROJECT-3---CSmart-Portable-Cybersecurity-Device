/*
  =====================================================================
  SMART PORTABLE CYBERSECURITY DEVICE  -  "SENTINEL"
  Board : ESP32-S3-N16R8 with onboard camera (Freenove ESP32-S3-WROOM CAM)
  =====================================================================

  SINGLE FILE. No extra library. No page.h. Just upload this.

  Arduino IDE settings
    Board            : ESP32S3 Dev Module
    PSRAM            : OPI PSRAM
    Flash Size       : 16MB (128Mb)
    Partition Scheme : Huge APP (3MB No OTA/1MB SPIFFS)
    USB CDC On Boot  : Enabled
    Upload Speed     : 921600

  WIRING
    Wi-Fi Button        GPIO 21  -> button -> GND
    URL Button          GPIO 41  -> button -> GND
    QR Button           GPIO 42  -> button -> GND
    Buzzer +            GPIO 47      Buzzer -  GND
    RGB Red             GPIO 1   -> 220-330 ohm -> R
    RGB Green           GPIO 14  -> 220-330 ohm -> G
    RGB Blue            GPIO 2   -> 220-330 ohm -> B
    RGB common cathode  GND
    Camera              onboard, no external wiring

  AFTER UPLOAD
    Open Serial Monitor at 115200. It prints the dashboard address.
    Open that address in any browser on the same Wi-Fi.

  CAMERA DESIGN
    Port 80  : dashboard, APIs, single JPEG snapshots
    Port 81  : MJPEG live stream in its own FreeRTOS task (low latency)
    Preview mode and QR mode never use the camera at the same time.
  =====================================================================
*/

#include <WiFi.h>
#include <WebServer.h>
#include "esp_camera.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

// ================== EDIT THESE TWO LINES ==================
const char *WIFI_SSID = "Jai";
const char *WIFI_PASS = "12345678";
// ==========================================================

// ---------------- PIN MAP ----------------
#define BTN_WIFI 21
#define BTN_URL  41
#define BTN_QR   42
#define BUZZER   47
#define LED_R    1
#define LED_G    14
#define LED_B    2

// ---------------- CAMERA PINS (Freenove ESP32-S3-WROOM CAM) ----------------
#define PWDN_GPIO_NUM  -1
#define RESET_GPIO_NUM -1
#define XCLK_GPIO_NUM  15
#define SIOD_GPIO_NUM  4
#define SIOC_GPIO_NUM  5
#define Y9_GPIO_NUM    16
#define Y8_GPIO_NUM    17
#define Y7_GPIO_NUM    18
#define Y6_GPIO_NUM    12
#define Y5_GPIO_NUM    10
#define Y4_GPIO_NUM    8
#define Y3_GPIO_NUM    9
#define Y2_GPIO_NUM    11
#define VSYNC_GPIO_NUM 6
#define HREF_GPIO_NUM  7
#define PCLK_GPIO_NUM  13

WebServer server(80);
SemaphoreHandle_t camMutex;

// ---------------- GLOBAL STATE ----------------
String secStatus   = "MONITORING";
String ledState    = "off";
String camState    = "CAMERA READY";
String wifiJson    = "[]";
String urlJson     = "{}";
String qrJson      = "{}";
String bestSSID    = "-";
int    curScore    = 0;
int    scanCount   = 0;
int    urlCount    = 0;
int    qrCount     = 0;
int    threatCount = 0;
int    netCount    = 0;
bool   cameraOK    = false;
volatile bool streamOn = true;
volatile unsigned long streamFrames = 0;
int previewSize    = FRAMESIZE_QVGA;  // live preview resolution
int previewQuality = 14;              // 10 = best, 40 = fastest
void applyCamMode(bool qr);
bool   qrRequest   = false;
bool   urlRequest  = false;
bool   wifiRequest = false;
unsigned long bootTime = 0;

#define HIST_MAX 14
String histType[HIST_MAX];
String histTarget[HIST_MAX];
String histRisk[HIST_MAX];
int    histScore[HIST_MAX];
unsigned long histTime[HIST_MAX];
int    histCount = 0;

// ================= UTILITIES =================
String jesc(String s) {
  String o = "";
  for (unsigned int i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"') o += "\\\"";
    else if (c == '\\') o += "\\\\";
    else if (c == '\n' || c == '\r') o += " ";
    else o += c;
  }
  return o;
}

void addEvent(String type, String target, int score, String risk) {
  if (histCount >= HIST_MAX) {
    for (int i = 0; i < HIST_MAX - 1; i++) {
      histType[i] = histType[i+1];
      histTarget[i] = histTarget[i+1];
      histRisk[i] = histRisk[i+1];
      histScore[i] = histScore[i+1];
      histTime[i] = histTime[i+1];
    }
    histCount = HIST_MAX - 1;
  }
  histType[histCount] = type;
  histTarget[histCount] = target;
  histRisk[histCount] = risk;
  histScore[histCount] = score;
  histTime[histCount] = (millis() - bootTime) / 1000;
  histCount++;
}

// ================= LED + BUZZER =================
void setColor(bool r, bool g, bool b) {
  digitalWrite(LED_R, r);
  digitalWrite(LED_G, g);
  digitalWrite(LED_B, b);
}
void ledOff()    { setColor(0,0,0); ledState = "off";    }
void ledGreen()  { setColor(0,1,0); ledState = "green";  }
void ledYellow() { setColor(1,1,0); ledState = "yellow"; }
void ledRed()    { setColor(1,0,0); ledState = "red";    }
void ledBlue()   { setColor(0,0,1); ledState = "blue";   }
void ledPurple() { setColor(1,0,1); ledState = "purple"; }

void beep(int times, int ms) {
  for (int i = 0; i < times; i++) {
    digitalWrite(BUZZER, HIGH); delay(ms);
    digitalWrite(BUZZER, LOW);  delay(ms);
  }
}

String riskFromScore(int s) {
  if (s < 30) return "LOW RISK";
  if (s < 60) return "SUSPICIOUS";
  if (s < 80) return "HIGH RISK";
  return "DANGEROUS";
}

void alertFor(int score) {
  curScore = score;
  if (score < 30)      { secStatus = "SECURE";     ledGreen();  beep(1, 70); }
  else if (score < 60) { secStatus = "SUSPICIOUS"; ledYellow(); beep(2, 110); threatCount++; }
  else                 { secStatus = "HIGH RISK";  ledRed();    beep(5, 90);  threatCount++; }
}

// ================= PHISHING URL ENGINE =================
// Heuristic, rule based, fully local. The device never opens the link.
struct Finding { String name; String status; bool bad; };
#define MAXF 24
Finding f[MAXF];
int fCount = 0;
void addF(String n, String s, bool bad) {
  if (fCount < MAXF) { f[fCount].name = n; f[fCount].status = s; f[fCount].bad = bad; fCount++; }
}

int analyseURL(String url) {
  fCount = 0;
  String u = url; u.toLowerCase();
  int pts = 0;

  // --- split the URL ---
  String rest = u;
  int pp = rest.indexOf("://");
  String scheme = "";
  if (pp >= 0) { scheme = rest.substring(0, pp); rest = rest.substring(pp + 3); }
  int sl = rest.indexOf('/');
  String host = (sl >= 0) ? rest.substring(0, sl) : rest;
  String path = (sl >= 0) ? rest.substring(sl) : "";
  int qm = path.indexOf('?');
  String query = (qm >= 0) ? path.substring(qm + 1) : "";
  if (qm >= 0) path = path.substring(0, qm);

  // --- port ---
  String portStr = "";
  int cp = host.indexOf(':');
  if (cp >= 0) { portStr = host.substring(cp + 1); host = host.substring(0, cp); }

  // 1 HTTPS
  if (scheme == "https") addF("HTTPS", "PASS", false);
  else if (scheme == "http") { pts += 14; addF("HTTPS", "MISSING", true); }
  else { pts += 8; addF("HTTPS", "UNKNOWN SCHEME", true); }

  // 2 URL length
  if (u.length() > 90) { pts += 8; addF("URL LENGTH", String(u.length()) + " CHARS - LONG", true); }
  else addF("URL LENGTH", String(u.length()) + " CHARS", false);

  // 3 domain length
  if (host.length() > 30) { pts += 6; addF("DOMAIN LENGTH", "UNUSUALLY LONG", true); }
  else addF("DOMAIN LENGTH", "NORMAL", false);

  // 4 IP address as host
  int dg = 0, dots = 0;
  for (unsigned int i = 0; i < host.length(); i++) {
    if (isDigit(host[i])) dg++;
    if (host[i] == '.') dots++;
  }
  if (dots == 3 && dg >= 4 && dg + dots == (int)host.length()) {
    pts += 20; addF("IP ADDRESS", "DETECTED", true);
  } else addF("IP ADDRESS", "NOT DETECTED", false);

  // 5 punycode
  if (host.indexOf("xn--") >= 0) { pts += 18; addF("PUNYCODE", "DETECTED", true); }
  else addF("PUNYCODE", "NOT DETECTED", false);

  // 6 subdomain depth
  if (dots >= 4)      { pts += 12; addF("SUBDOMAINS", "EXCESSIVE", true); }
  else if (dots == 3) { pts += 6;  addF("SUBDOMAINS", "ELEVATED", true); }
  else addF("SUBDOMAINS", "NORMAL", false);

  // 7 hyphens
  int hy = 0;
  for (unsigned int i = 0; i < host.length(); i++) if (host[i] == '-') hy++;
  if (hy >= 3)      { pts += 10; addF("HYPHENS", "EXCESSIVE", true); }
  else if (hy == 2) { pts += 5;  addF("HYPHENS", "ELEVATED", true); }
  else addF("HYPHENS", "NORMAL", false);

  // 8 digits inside domain
  if (dg >= 5 && dots < 3) { pts += 7; addF("DIGITS IN DOMAIN", "EXCESSIVE", true); }
  else addF("DIGITS IN DOMAIN", "NORMAL", false);

  // 9 at symbol
  if (u.indexOf('@') >= 0) { pts += 18; addF("REDIRECT TRICK", "AT SYMBOL FOUND", true); }
  else addF("REDIRECT TRICK", "NOT DETECTED", false);

  // 10 unusual port
  if (portStr.length() > 0 && portStr != "80" && portStr != "443") {
    pts += 10; addF("PORT", "UNUSUAL PORT " + portStr, true);
  } else addF("PORT", "STANDARD", false);

  // 11 query string
  if (query.length() > 60) { pts += 6; addF("QUERY STRING", "VERY LONG", true); }
  else addF("QUERY STRING", "NORMAL", false);

  // 12 suspicious parameters
  const char *pr[] = {"token=","session=","redirect=","return=","next=","pwd=","passwd="};
  bool prBad = false;
  for (unsigned int i = 0; i < sizeof(pr)/sizeof(pr[0]); i++)
    if (query.indexOf(pr[i]) >= 0) { prBad = true; break; }
  if (prBad) { pts += 7; addF("PARAMETERS", "SENSITIVE PARAM FOUND", true); }
  else addF("PARAMETERS", "NOT DETECTED", false);

  // 13 keyword families
  const char *kLogin[] = {"login","signin","logon","auth"};
  const char *kVerify[] = {"verify","verification","confirm","validate","update"};
  const char *kPay[] = {"payment","wallet","bank","billing","invoice","upi","paytm"};
  const char *kPass[] = {"password","passwd","credential","pin","otp"};
  const char *kUrg[] = {"urgent","suspended","locked","expire","immediately","alert"};
  const char *kBait[] = {"free","bonus","prize","winner","claim","gift","reward","offer"};

  int kHits = 0;
  String kList = "";
  struct { const char **arr; int n; const char *label; int w; } fam[] = {
    { kLogin,  4, "LOGIN",        7 },
    { kVerify, 5, "VERIFICATION", 7 },
    { kPay,    7, "PAYMENT",      8 },
    { kPass,   5, "PASSWORD",     9 },
    { kUrg,    6, "URGENCY",      6 },
    { kBait,   8, "BAIT",         6 }
  };
  for (int g = 0; g < 6; g++) {
    for (int i = 0; i < fam[g].n; i++) {
      if (u.indexOf(fam[g].arr[i]) >= 0) {
        pts += fam[g].w; kHits++;
        if (kList.length()) kList += ", ";
        kList += String(fam[g].arr[i]);
        break;
      }
    }
  }
  if (kHits > 0) addF("SUSPICIOUS KEYWORDS", "DETECTED - " + kList, true);
  else addF("SUSPICIOUS KEYWORDS", "NOT DETECTED", false);

  // 14 brand impersonation / typo squat
  const char *bi[] = {"payp","g00gle","faceb00k","arnazon","micros0ft","1nstagram",
                      "paytrn","app1e","netfliix","whatsapp-","sbi-","hdfc-"};
  bool biBad = false;
  for (unsigned int i = 0; i < sizeof(bi)/sizeof(bi[0]); i++)
    if (host.indexOf(bi[i]) >= 0) { biBad = true; break; }
  if (biBad) { pts += 20; addF("BRAND IMPERSONATION", "DETECTED", true); }
  else addF("BRAND IMPERSONATION", "NOT DETECTED", false);

  // 15 risky TLD
  const char *tl[] = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".zip",".click",".work"};
  bool tlBad = false;
  String tlName = "";
  for (unsigned int i = 0; i < sizeof(tl)/sizeof(tl[0]); i++)
    if (host.endsWith(tl[i])) { tlBad = true; tlName = String(tl[i]); break; }
  if (tlBad) { pts += 12; addF("TOP LEVEL DOMAIN", "HIGH RISK " + tlName, true); }
  else addF("TOP LEVEL DOMAIN", "NORMAL", false);

  // 16 shortener
  const char *sh[] = {"bit.ly","tinyurl","t.co","goo.gl","is.gd","rb.gy","cutt.ly","shorturl"};
  bool shBad = false;
  for (unsigned int i = 0; i < sizeof(sh)/sizeof(sh[0]); i++)
    if (host.indexOf(sh[i]) >= 0) { shBad = true; break; }
  if (shBad) { pts += 12; addF("URL SHORTENER", "DETECTED - TARGET HIDDEN", true); }
  else addF("URL SHORTENER", "NOT DETECTED", false);

  // 17 dangerous path
  if (path.endsWith(".exe") || path.endsWith(".apk") || path.endsWith(".scr") ||
      path.endsWith(".bat") || path.endsWith(".msi")) {
    pts += 20; addF("FILE DOWNLOAD", "EXECUTABLE DETECTED", true);
  } else addF("FILE DOWNLOAD", "NOT DETECTED", false);

  // 18 suspicious characters
  if (u.indexOf("%00") >= 0 || u.indexOf("//") != u.lastIndexOf("//")) {
    pts += 8; addF("ENCODED CHARACTERS", "SUSPICIOUS SEQUENCE", true);
  } else addF("ENCODED CHARACTERS", "NOT DETECTED", false);

  if (pts > 100) pts = 100;
  return pts;
}

String buildURLJson(String url, int score, String type) {
  String j = "{\"url\":\"" + jesc(url) + "\",\"type\":\"" + type + "\",";
  j += "\"score\":" + String(score) + ",";
  j += "\"risk\":\"" + riskFromScore(score) + "\",\"items\":[";
  for (int i = 0; i < fCount; i++) {
    if (i) j += ",";
    j += "{\"n\":\"" + jesc(f[i].name) + "\",\"s\":\"" + jesc(f[i].status) +
         "\",\"b\":" + String(f[i].bad ? "true" : "false") + "}";
  }
  j += "]}";
  return j;
}

void runURLCheck(String url, bool fromQR) {
  ledBlue();
  int score = analyseURL(url);
  String type = (url.startsWith("http") || url.indexOf("www.") >= 0) ? "URL" : "TEXT";
  String js = buildURLJson(url, score, type);
  if (fromQR) { qrJson = js; qrCount++; addEvent("QR CODE", url, score, riskFromScore(score)); }
  else        { urlJson = js; urlCount++; addEvent("URL SCAN", url, score, riskFromScore(score)); }
  alertFor(score);
  Serial.println("URL " + url + " -> " + String(score) + " " + riskFromScore(score));
}

// ================= WI-FI RISK ASSESSMENT =================
void runWiFiScan() {
  ledBlue();
  camState = "CAMERA READY";
  scanCount++;
  Serial.println("Scanning Wi-Fi...");

  int n = WiFi.scanNetworks();
  netCount = (n > 0) ? n : 0;
  if (n <= 0) {
    wifiJson = "[]";
    secStatus = "MONITORING";
    bestSSID = "-";
    ledYellow();
    addEvent("WIFI SCAN", "no networks", 0, "LOW RISK");
    return;
  }

  int bestIdx = 0, bestSc = -1;
  String out = "[";

  for (int i = 0; i < n; i++) {
    int risk = 0;
    String enc, note = "";
    wifi_auth_mode_t e = WiFi.encryptionType(i);

    if (e == WIFI_AUTH_OPEN)               { enc = "OPEN";   risk += 60; note += "No encryption. "; }
    else if (e == WIFI_AUTH_WEP)           { enc = "WEP";    risk += 55; note += "Broken WEP cipher. "; }
    else if (e == WIFI_AUTH_WPA_PSK)       { enc = "WPA";    risk += 35; note += "Outdated WPA. "; }
    else if (e == WIFI_AUTH_WPA2_PSK)      { enc = "WPA2";   risk += 10; }
    else if (e == WIFI_AUTH_WPA3_PSK)      { enc = "WPA3";   risk += 2;  }
    else if (e == WIFI_AUTH_WPA2_WPA3_PSK) { enc = "WPA2/3"; risk += 5;  }
    else                                   { enc = "OTHER";  risk += 20; }

    int rssi = WiFi.RSSI(i);
    String q;
    if (rssi > -55)      { q = "EXCELLENT"; }
    else if (rssi > -65) { q = "GOOD"; risk += 3; }
    else if (rssi > -75) { q = "FAIR"; risk += 8; }
    else                 { q = "WEAK"; risk += 14; }

    for (int j = 0; j < n; j++) {
      if (j != i && WiFi.SSID(j) == WiFi.SSID(i) && WiFi.BSSIDstr(j) != WiFi.BSSIDstr(i)) {
        risk += 30; note += "Duplicate SSID, possible evil twin. "; break;
      }
    }

    String ls = WiFi.SSID(i); ls.toLowerCase();
    if (ls.length() == 0) { risk += 15; note += "Hidden SSID. "; }
    if (ls.indexOf("free") >= 0 || ls.indexOf("public") >= 0 ||
        ls.indexOf("open") >= 0 || ls.indexOf("guest") >= 0) {
      risk += 12; note += "Bait style network name. ";
    }
    if (risk > 100) risk = 100;
    if (note == "") note = "No abnormal indicator observed.";

    String lvl = (risk < 25) ? "LOW" : (risk < 55 ? "MODERATE" : "HIGH");
    String nm = WiFi.SSID(i);
    if (nm.length() == 0) nm = "hidden network";

    if (i) out += ",";
    out += "{\"ssid\":\"" + jesc(nm) + "\",\"rssi\":" + String(rssi) +
           ",\"ch\":" + String(WiFi.channel(i)) + ",\"enc\":\"" + enc +
           "\",\"q\":\"" + q + "\",\"risk\":\"" + lvl + "\",\"score\":" + String(risk) +
           ",\"note\":\"" + jesc(note) + "\"}";

    if (bestSc < 0 || risk < bestSc) { bestSc = risk; bestIdx = i; }
  }
  out += "]";
  wifiJson = out;

  bestSSID = WiFi.SSID(bestIdx);
  if (bestSSID.length() == 0) bestSSID = "hidden network";

  // overall environment score = risk of the worst network present
  int envRisk = 0;
  for (int i = 0; i < n; i++) {
    wifi_auth_mode_t e = WiFi.encryptionType(i);
    int r = (e == WIFI_AUTH_OPEN) ? 70 : (e == WIFI_AUTH_WEP ? 65 : (e == WIFI_AUTH_WPA_PSK ? 40 : 10));
    if (r > envRisk) envRisk = r;
  }
  alertFor(envRisk);
  addEvent("WIFI SCAN", String(n) + " networks, best " + bestSSID, envRisk, riskFromScore(envRisk));
  Serial.println("Recommended network: " + bestSSID);
  WiFi.scanDelete();
}

// ================= CAMERA =================
bool startCamera() {
  camera_config_t c;
  c.ledc_channel = LEDC_CHANNEL_0;
  c.ledc_timer   = LEDC_TIMER_0;
  c.pin_d0 = Y2_GPIO_NUM;  c.pin_d1 = Y3_GPIO_NUM;
  c.pin_d2 = Y4_GPIO_NUM;  c.pin_d3 = Y5_GPIO_NUM;
  c.pin_d4 = Y6_GPIO_NUM;  c.pin_d5 = Y7_GPIO_NUM;
  c.pin_d6 = Y8_GPIO_NUM;  c.pin_d7 = Y9_GPIO_NUM;
  c.pin_xclk = XCLK_GPIO_NUM;     c.pin_pclk = PCLK_GPIO_NUM;
  c.pin_vsync = VSYNC_GPIO_NUM;   c.pin_href = HREF_GPIO_NUM;
  c.pin_sccb_sda = SIOD_GPIO_NUM; c.pin_sccb_scl = SIOC_GPIO_NUM;
  c.pin_pwdn = PWDN_GPIO_NUM;     c.pin_reset = RESET_GPIO_NUM;
  c.xclk_freq_hz = 20000000;
  c.pixel_format = PIXFORMAT_JPEG;
  // IMPORTANT: the driver sizes its frame buffers from this value at init.
  // Initialise at the LARGEST size we will ever use (VGA, for QR capture),
  // then step down to QVGA for the preview. Asking for a size bigger than
  // the one used here makes esp_camera_fb_get() return NULL.
  c.frame_size   = FRAMESIZE_VGA;
  c.jpeg_quality = 12;
  c.fb_count     = 2;
  c.fb_location  = CAMERA_FB_IN_PSRAM;
  c.grab_mode    = CAMERA_GRAB_LATEST;

  esp_err_t err = esp_camera_init(&c);
  if (err != ESP_OK) {
    Serial.printf("Camera init failed 0x%x\n", err);
    camState = "CAMERA ERROR";
    return false;
  }
  applyCamMode(false);
  camState = "CAMERA READY";
  return true;
}

// PREVIEW MODE : QVGA 320x240, quality 12  -> small frames, low latency
// QR MODE      : VGA  640x480, quality 10  -> detail the decoder needs
void applyCamMode(bool qr) {
  sensor_t *s = esp_camera_sensor_get();
  if (!s) return;
  if (qr) {
    s->set_framesize(s, FRAMESIZE_VGA);
    s->set_quality(s, 10);
  } else {
    s->set_framesize(s, (framesize_t)previewSize);
    s->set_quality(s, previewQuality);
  }
  // sharper edges help the QR decoder and cost nothing in preview
  s->set_contrast(s, qr ? 2 : 0);
  s->set_brightness(s, qr ? 1 : 0);
}

// ---- MJPEG stream task on port 81 (keeps port 80 responsive) ----
void streamTask(void *pv) {
  WiFiServer sserver(81);
  sserver.begin();
  char hdr[72];
  for (;;) {
    WiFiClient client = sserver.available();
    if (client) {
      client.setNoDelay(true);          // no Nagle delay: this is the big latency win
      camState = "LIVE PREVIEW";
      const char *head =
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "Content-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n";
      client.write((const uint8_t *)head, strlen(head));

      while (client.connected() && streamOn && cameraOK) {
        if (xSemaphoreTake(camMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
          camera_fb_t *fb = esp_camera_fb_get();
          if (fb) {
            int n = snprintf(hdr, sizeof hdr,
              "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %u\r\n\r\n",
              (unsigned)fb->len);
            client.write((const uint8_t *)hdr, n);
            client.write(fb->buf, fb->len);
            client.write((const uint8_t *)"\r\n", 2);
            esp_camera_fb_return(fb);
            streamFrames++;
          }
          xSemaphoreGive(camMutex);
        }
        // yield one tick only; the camera itself paces the loop
        vTaskDelay(1);
      }
      client.stop();
      camState = cameraOK ? "CAMERA READY" : "CAMERA ERROR";
    }
    vTaskDelay(pdMS_TO_TICKS(15));
  }
}

// ---- single snapshot on port 80, used by the QR decoder ----
void handleSnap() {
  if (!cameraOK) { server.send(503, "text/plain", "no camera"); return; }
  // generous wait: the stream task releases the mutex every frame
  if (xSemaphoreTake(camMutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
    server.send(503, "text/plain", "busy"); return;
  }
  camera_fb_t *fb = esp_camera_fb_get();
  if (!fb) {                      // one retry: the sensor may still be resyncing
    vTaskDelay(pdMS_TO_TICKS(60));
    fb = esp_camera_fb_get();
  }
  if (!fb) {
    xSemaphoreGive(camMutex);
    Serial.println("snap: frame grab failed");
    server.send(503, "text/plain", "fail");
    return;
  }
  WiFiClient client = server.client();
  client.setNoDelay(true);
  server.setContentLength(fb->len);
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "image/jpeg", "");
  client.write(fb->buf, fb->len);
  esp_camera_fb_return(fb);
  xSemaphoreGive(camMutex);
}

// ---- camera mode switch: the dashboard calls this before and after QR ----
void handleCamMode() {
  String m = server.arg("mode");
  String fs = server.arg("fs");
  if (fs.length()) {                       // live resolution change
    if (fs == "qqvga")     { previewSize = FRAMESIZE_QQVGA; previewQuality = 14; }
    else if (fs == "qvga") { previewSize = FRAMESIZE_QVGA;  previewQuality = 14; }
    else if (fs == "hvga") { previewSize = FRAMESIZE_HVGA;  previewQuality = 13; }
    else if (fs == "vga")  { previewSize = FRAMESIZE_VGA;   previewQuality = 12; }
    applyCamMode(false);
    server.send(200, "application/json", String("{\"fs\":\"") + fs + "\"}");
    return;
  }
  if (m == "qr") {
    streamOn = false;            // stop the stream so the sensor is free
    delay(120);                  // let the stream task close its client
    applyCamMode(true);
    camState = "QR SCANNING";
    ledBlue();
  } else {
    applyCamMode(false);
    streamOn = true;
    camState = "CAMERA READY";
  }
  server.send(200, "application/json",
              String("{\"mode\":\"") + (m == "qr" ? "qr" : "preview") + "\"}");
}

// =====================================================================
//                        DASHBOARD  (no apostrophes)
// =====================================================================
const char PAGE[] PROGMEM =
"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>Smart Portable Cybersecurity Device</title>\n"
"<style>\n"
"*{box-sizing:border-box;margin:0;padding:0}\n"
":root{\n"
"--bg:#060912;--pan:#0d1322;--pan2:#111a2e;--br:#1e2a44;\n"
"--txt:#e9eefc;--dim:#7d8db4;--dim2:#56648a;\n"
"--acc:#4f8cff;--acc2:#8b5cf6;\n"
"--ok:#22c55e;--wn:#eab308;--hi:#f97316;--bad:#ef4444}\n"
"body{font-family:\"Inter\",\"Segoe UI\",system-ui,-apple-system,sans-serif;\n"
"background:var(--bg);color:var(--txt);min-height:100vh;font-size:14px;\n"
"background-image:radial-gradient(1100px 600px at 8% -5%,rgba(79,140,255,.10),transparent 62%),\n"
"radial-gradient(1000px 600px at 100% 105%,rgba(139,92,246,.10),transparent 62%)}\n"
".shell{max-width:1180px;margin:auto;padding:20px 18px 40px}\n"
"\n"
"/* ---------- header ---------- */\n"
"header{display:flex;align-items:center;gap:13px;padding:6px 0 18px;flex-wrap:wrap}\n"
".mark{width:42px;height:42px;border-radius:12px;flex:none;position:relative;\n"
"background:linear-gradient(145deg,var(--acc),var(--acc2));\n"
"display:flex;align-items:center;justify-content:center;\n"
"box-shadow:0 6px 22px rgba(79,140,255,.33)}\n"
".mark svg{width:21px;height:21px}\n"
".htxt h1{font-size:17px;font-weight:650;letter-spacing:.2px;line-height:1.25}\n"
".htxt p{font-size:11px;color:var(--dim2);letter-spacing:1.3px;text-transform:uppercase;margin-top:2px}\n"
".sp{flex:1}\n"
".pill{font-size:10.5px;padding:6px 12px;border-radius:30px;background:var(--pan);\n"
"border:1px solid var(--br);color:#9eb0d6;letter-spacing:.7px;white-space:nowrap;font-weight:500}\n"
".pill.on{color:#4ade80;border-color:rgba(34,197,94,.3);background:rgba(34,197,94,.07)}\n"
"\n"
"/* ---------- status strip ---------- */\n"
".strip{display:flex;align-items:center;gap:15px;background:var(--pan);\n"
"border:1px solid var(--br);border-radius:15px;padding:16px 19px;margin-bottom:13px;flex-wrap:wrap}\n"
".led{width:14px;height:14px;border-radius:50%;background:#28324e;flex:none;transition:.25s}\n"
".led.green{background:var(--ok);box-shadow:0 0 0 4px rgba(34,197,94,.14),0 0 16px var(--ok)}\n"
".led.yellow{background:var(--wn);box-shadow:0 0 0 4px rgba(234,179,8,.14),0 0 16px var(--wn)}\n"
".led.red{background:var(--bad);box-shadow:0 0 0 4px rgba(239,68,68,.14),0 0 16px var(--bad);animation:pz 1s infinite}\n"
".led.blue{background:var(--acc);box-shadow:0 0 0 4px rgba(79,140,255,.14),0 0 16px var(--acc);animation:pz 1.4s infinite}\n"
".led.purple{background:var(--acc2);box-shadow:0 0 0 4px rgba(139,92,246,.14),0 0 16px var(--acc2);animation:pz 1.2s infinite}\n"
"@keyframes pz{50%{opacity:.35}}\n"
".stv{font-weight:700;font-size:15px;letter-spacing:.8px}\n"
".stsub{font-size:11px;color:var(--dim2);margin-top:2px}\n"
".meterwrap{display:flex;align-items:center;gap:11px;min-width:190px}\n"
".mtr{flex:1;height:7px;background:#0a1020;border-radius:4px;overflow:hidden;border:1px solid var(--br)}\n"
".mtr i{display:block;height:100%;width:0;border-radius:4px;transition:width .5s,background .3s}\n"
".mval{font-size:12px;font-weight:700;letter-spacing:.4px;min-width:58px;text-align:right}\n"
"\n"
"/* ---------- kpis ---------- */\n"
".kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:11px;margin-bottom:16px}\n"
"@media(max-width:720px){.kpis{grid-template-columns:repeat(2,1fr)}}\n"
".kpi{background:var(--pan);border:1px solid var(--br);border-radius:14px;padding:15px 14px;\n"
"position:relative;overflow:hidden}\n"
".kpi:before{content:\"\";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--acc);opacity:.65}\n"
".kpi.k2:before{background:#38bdf8}.kpi.k3:before{background:var(--acc2)}\n"
".kpi.k4:before{background:#f472b6}.kpi.k5:before{background:var(--bad)}\n"
".kpi b{display:block;font-size:25px;font-weight:700;line-height:1.1;letter-spacing:-.5px}\n"
".kpi span{font-size:9.5px;color:var(--dim2);text-transform:uppercase;letter-spacing:1.1px;\n"
"margin-top:5px;display:block}\n"
"\n"
"/* ---------- nav ---------- */\n"
"nav{display:flex;gap:6px;overflow-x:auto;padding-bottom:12px;margin-bottom:15px;\n"
"scrollbar-width:none}\n"
"nav::-webkit-scrollbar{display:none}\n"
"nav div{padding:10px 17px;border-radius:10px;cursor:pointer;font-size:12.5px;white-space:nowrap;\n"
"background:var(--pan);border:1px solid var(--br);transition:.16s;color:#a6b6da;font-weight:500}\n"
"nav div:hover{border-color:#2d3d60;color:#d4def5}\n"
"nav div.on{background:linear-gradient(135deg,var(--acc),var(--acc2));border-color:transparent;\n"
"color:#fff;font-weight:600;box-shadow:0 4px 16px rgba(79,140,255,.28)}\n"
"\n"
"/* ---------- cards ---------- */\n"
".pg{display:none}.pg.on{display:block}\n"
".card{background:var(--pan);border:1px solid var(--br);border-radius:16px;padding:20px;margin-bottom:13px}\n"
".card h3{font-size:11px;letter-spacing:1.4px;color:var(--dim);text-transform:uppercase;\n"
"margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--br);font-weight:600;\n"
"display:flex;align-items:center;gap:9px}\n"
".card h3 em{font-style:normal;margin-left:auto;color:var(--dim2);letter-spacing:.5px;\n"
"text-transform:none;font-size:11px}\n"
".two{display:grid;grid-template-columns:1.05fr .95fr;gap:13px}\n"
"@media(max-width:860px){.two{grid-template-columns:1fr}}\n"
"\n"
"button{background:linear-gradient(135deg,var(--acc),var(--acc2));border:0;color:#fff;\n"
"padding:12px 21px;border-radius:10px;font-size:12.5px;font-weight:600;cursor:pointer;\n"
"letter-spacing:.5px;font-family:inherit;transition:.15s}\n"
"button:hover{filter:brightness(1.1)}\n"
"button:active{transform:scale(.975)}\n"
"button.gh{background:var(--pan2);border:1px solid var(--br);color:#aebbd8}\n"
"button.gh:hover{border-color:#36476d;color:#dde5f8}\n"
"button.sm{padding:8px 14px;font-size:11px}\n"
"input,select{width:100%;padding:13px 14px;border-radius:10px;border:1px solid var(--br);\n"
"background:#080d19;color:#fff;font-size:13.5px;outline:none;font-family:inherit;transition:.15s}\n"
"input:focus,select:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,140,255,.13)}\n"
"select{width:auto;padding:9px 12px;font-size:11.5px;cursor:pointer}\n"
".row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}\n"
"\n"
"/* ---------- table ---------- */\n"
".tw{overflow-x:auto;margin:0 -4px}\n"
"table{width:100%;border-collapse:collapse;font-size:12.5px}\n"
"th{text-align:left;padding:11px 10px;color:var(--dim2);font-size:9.5px;letter-spacing:1.1px;\n"
"text-transform:uppercase;border-bottom:1px solid var(--br);font-weight:600;white-space:nowrap}\n"
"td{padding:13px 10px;border-bottom:1px solid #141d33;vertical-align:middle}\n"
"tbody tr:hover td{background:#0f1728}\n"
"tr.best td{background:rgba(34,197,94,.055)}\n"
"tr.best td:first-child{box-shadow:inset 3px 0 0 var(--ok)}\n"
".ssid{font-weight:600;font-size:13px}\n"
".mono{font-variant-numeric:tabular-nums}\n"
".tag{font-size:9.5px;padding:4px 10px;border-radius:20px;font-weight:700;letter-spacing:.6px;\n"
"display:inline-block;white-space:nowrap}\n"
".t-LOW,.t-ok{background:rgba(34,197,94,.15);color:#4ade80}\n"
".t-MODERATE,.t-wn{background:rgba(234,179,8,.15);color:#facc15}\n"
".t-HIGH,.t-bad{background:rgba(239,68,68,.15);color:#f87171}\n"
".t-info{background:rgba(79,140,255,.15);color:#8ab4ff}\n"
".sig{display:inline-flex;align-items:flex-end;gap:2px;height:14px;vertical-align:-2px;margin-right:7px}\n"
".sig i{width:3px;background:#263253;border-radius:1px}\n"
".sig i.a{background:#5f9bff}\n"
".rec{color:var(--dim2);font-size:11.5px;line-height:1.5;max-width:300px}\n"
".rec b{color:#4ade80;font-weight:600}\n"
"\n"
"/* ---------- score ring ---------- */\n"
".gauge{display:flex;align-items:center;gap:20px;flex-wrap:wrap;\n"
"background:#0a1120;border:1px solid var(--br);border-radius:14px;padding:18px;margin-bottom:16px}\n"
".ring{width:104px;height:104px;border-radius:50%;flex:none;position:relative}\n"
".ring i{position:absolute;inset:8px;border-radius:50%;background:#0a1120;\n"
"display:flex;align-items:center;justify-content:center;flex-direction:column;font-style:normal}\n"
".ring b{font-size:27px;font-weight:700;line-height:1}\n"
".ring small{font-size:8.5px;color:var(--dim2);letter-spacing:1.2px;margin-top:3px}\n"
".gmeta h4{font-size:20px;font-weight:700;letter-spacing:.8px;margin-bottom:6px}\n"
".gmeta p{font-size:11.5px;color:var(--dim2);line-height:1.6;max-width:330px}\n"
"\n"
"/* ---------- indicator list ---------- */\n"
".vlist{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:7px}\n"
"@media(max-width:760px){.vlist{grid-template-columns:1fr}}\n"
".vlist li{display:flex;justify-content:space-between;align-items:center;gap:10px;\n"
"padding:11px 13px;background:#0a1120;border-radius:9px;font-size:12px;\n"
"border-left:3px solid var(--ok)}\n"
".vlist li.b{border-left-color:var(--bad);background:rgba(239,68,68,.045)}\n"
".vlist li em{font-style:normal;color:#b9c6e4;font-weight:500}\n"
".vlist li span{color:var(--dim2);font-size:10.5px;text-align:right;letter-spacing:.3px}\n"
".vlist li.b span{color:#f8a5a5}\n"
"\n"
"/* ---------- camera ---------- */\n"
".camwrap{position:relative;max-width:560px;margin:0 auto;border-radius:13px;\n"
"overflow:hidden;border:1px solid var(--br);background:#05080f}\n"
".camwrap:before{content:\"\";display:block;padding-top:75%}\n"
".cam{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;display:block}\n"
".camoff{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;\n"
"flex-direction:column;gap:9px;color:var(--dim2);font-size:12px;letter-spacing:.8px;\n"
"background:#05080f;text-align:center;padding:16px}\n"
".camoff.hide{display:none}\n"
".spin{width:26px;height:26px;border:2px solid #22304d;border-top-color:var(--acc);\n"
"border-radius:50%;animation:sp .8s linear infinite}\n"
"@keyframes sp{to{transform:rotate(360deg)}}\n"
".scanbox{position:absolute;inset:14%;border-radius:10px;pointer-events:none;display:none}\n"
".scanbox.on{display:block}\n"
".scanbox span{position:absolute;width:26px;height:26px;border:2.5px solid var(--acc)}\n"
".scanbox span:nth-child(1){top:0;left:0;border-right:0;border-bottom:0;border-radius:8px 0 0 0}\n"
".scanbox span:nth-child(2){top:0;right:0;border-left:0;border-bottom:0;border-radius:0 8px 0 0}\n"
".scanbox span:nth-child(3){bottom:0;left:0;border-right:0;border-top:0;border-radius:0 0 0 8px}\n"
".scanbox span:nth-child(4){bottom:0;right:0;border-left:0;border-top:0;border-radius:0 0 8px 0}\n"
".scanline{position:absolute;left:0;right:0;height:2px;\n"
"background:linear-gradient(90deg,transparent,var(--acc),transparent);animation:sl 2s ease-in-out infinite}\n"
"@keyframes sl{0%,100%{top:0}50%{top:calc(100% - 2px)}}\n"
"\n"
"/* ---------- misc ---------- */\n"
".note{font-size:11px;color:var(--dim2);line-height:1.75;margin-top:13px}\n"
".disc{font-size:11px;color:#8fa0c6;line-height:1.8;background:rgba(79,140,255,.055);\n"
"border:1px solid rgba(79,140,255,.2);border-radius:11px;padding:15px}\n"
".kv{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:11px 0;\n"
"border-bottom:1px solid #141d33;font-size:12.5px}\n"
".kv:last-child{border-bottom:0}\n"
".kv span:first-child{color:var(--dim2)}\n"
".kv span:last-child{font-weight:500;text-align:right;word-break:break-word}\n"
".keys{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}\n"
".key{background:#0a1120;border:1px solid var(--br);border-radius:11px;padding:13px 10px;\n"
"text-align:center;font-size:10px;color:var(--dim2);letter-spacing:.6px}\n"
".key b{display:block;color:#cfdcf8;font-size:12.5px;margin-bottom:4px;letter-spacing:.3px}\n"
".lg{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px}\n"
".lg div{font-size:10.5px;color:var(--dim2);display:flex;align-items:center;gap:7px;letter-spacing:.5px}\n"
".lg i{width:9px;height:9px;border-radius:50%;display:inline-block;flex:none}\n"
".empty{color:var(--dim2);font-size:12.5px;padding:26px 14px;text-align:center}\n"
".ft{text-align:center;color:#394867;font-size:10.5px;letter-spacing:1px;padding:18px 0 4px}\n"
"</style></head><body><div class=\"shell\">\n"
"\n"
"<header>\n"
" <div class=\"mark\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#fff\" stroke-width=\"2\"\n"
"  stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/>\n"
"  <path d=\"M9 12l2 2 4-4\"/></svg></div>\n"
" <div class=\"htxt\">\n"
"  <h1>Smart Portable Cybersecurity Device</h1>\n"
"  <p>ESP32-S3 &middot; Wi-Fi &middot; URL &middot; QR Security Analysis</p>\n"
" </div>\n"
" <div class=\"sp\"></div>\n"
" <div class=\"pill on\" id=\"pOn\">ONLINE</div>\n"
" <div class=\"pill\" id=\"pCam\">CAMERA</div>\n"
" <div class=\"pill\" id=\"pFps\">0 FPS</div>\n"
" <div class=\"pill\" id=\"pUp\">0s</div>\n"
"</header>\n"
"\n"
"<div class=\"strip\">\n"
" <div class=\"led\" id=\"led\"></div>\n"
" <div>\n"
"  <div class=\"stv\" id=\"stv\">MONITORING</div>\n"
"  <div class=\"stsub\" id=\"stsub\">Awaiting a security scan</div>\n"
" </div>\n"
" <div class=\"sp\"></div>\n"
" <div class=\"meterwrap\">\n"
"  <div class=\"mtr\"><i id=\"mtr\"></i></div>\n"
"  <div class=\"mval\" id=\"mval\">0/100</div>\n"
" </div>\n"
" <div class=\"pill\" id=\"pIp\">--</div>\n"
"</div>\n"
"\n"
"<div class=\"kpis\">\n"
" <div class=\"kpi k1\"><b id=\"k1\">0</b><span>Wi-Fi Scans</span></div>\n"
" <div class=\"kpi k2\"><b id=\"k2\">0</b><span>Networks Seen</span></div>\n"
" <div class=\"kpi k3\"><b id=\"k3\">0</b><span>URLs Checked</span></div>\n"
" <div class=\"kpi k4\"><b id=\"k4\">0</b><span>QR Scans</span></div>\n"
" <div class=\"kpi k5\"><b id=\"k5\">0</b><span>Threats Flagged</span></div>\n"
"</div>\n"
"\n"
"<nav>\n"
" <div class=\"on\" onclick=\"go(0)\">Dashboard</div>\n"
" <div onclick=\"go(1)\">Wi-Fi Security</div>\n"
" <div onclick=\"go(2)\">URL Security</div>\n"
" <div onclick=\"go(3)\">QR Scanner</div>\n"
" <div onclick=\"go(4)\">Camera</div>\n"
" <div onclick=\"go(5)\">Threat History</div>\n"
" <div onclick=\"go(6)\">Device Status</div>\n"
" <div onclick=\"go(7)\">About</div>\n"
"</nav>\n"
"\n"
"<!-- 0 DASHBOARD -->\n"
"<div class=\"pg on\" id=\"p0\">\n"
" <div class=\"two\">\n"
"  <div class=\"card\"><h3>Live Camera<em id=\"fps0\">0 fps</em></h3>\n"
"   <div class=\"camwrap\">\n"
"    <img class=\"cam\" id=\"cam0\" alt=\"\">\n"
"    <div class=\"camoff\" id=\"off0\"><div class=\"spin\"></div><div>CONNECTING TO CAMERA</div></div>\n"
"   </div>\n"
"   <div class=\"row\" style=\"margin-top:13px;justify-content:center\">\n"
"    <select id=\"res\" onchange=\"setRes()\">\n"
"     <option value=\"qqvga\">160 x 120 - fastest</option>\n"
"     <option value=\"qvga\" selected>320 x 240 - balanced</option>\n"
"     <option value=\"hvga\">480 x 320 - sharper</option>\n"
"     <option value=\"vga\">640 x 480 - best quality</option>\n"
"    </select>\n"
"    <button class=\"gh sm\" onclick=\"restartCam()\">Reconnect</button>\n"
"   </div>\n"
"  </div>\n"
"  <div class=\"card\"><h3>Quick Actions</h3>\n"
"   <div class=\"row\" style=\"margin-bottom:17px\">\n"
"    <button onclick=\"go(1);scanWifi()\">Scan Wi-Fi</button>\n"
"    <button class=\"gh\" onclick=\"go(3)\">Scan QR</button>\n"
"    <button class=\"gh\" onclick=\"go(2)\">Analyse URL</button>\n"
"   </div>\n"
"   <div class=\"kv\"><span>Latest Wi-Fi result</span><span id=\"lw\">no scan yet</span></div>\n"
"   <div class=\"kv\"><span>Latest URL result</span><span id=\"lu\">no scan yet</span></div>\n"
"   <div class=\"kv\"><span>Latest QR result</span><span id=\"lq\">no scan yet</span></div>\n"
"   <div class=\"kv\"><span>Latest event</span><span id=\"le\">system started</span></div>\n"
"   <div class=\"kv\"><span>Security status</span><span id=\"ls\">MONITORING</span></div>\n"
"  </div>\n"
" </div>\n"
" <div class=\"card\"><h3>Hardware Controls</h3>\n"
"  <div class=\"keys\">\n"
"   <div class=\"key\"><b>GPIO 21</b>WI-FI SCAN</div>\n"
"   <div class=\"key\"><b>GPIO 41</b>URL ANALYSIS</div>\n"
"   <div class=\"key\"><b>GPIO 42</b>QR SCAN</div>\n"
"  </div>\n"
"  <div class=\"lg\">\n"
"   <div><i style=\"background:#22c55e\"></i>SAFE</div>\n"
"   <div><i style=\"background:#eab308\"></i>SUSPICIOUS</div>\n"
"   <div><i style=\"background:#ef4444\"></i>HIGH RISK</div>\n"
"   <div><i style=\"background:#4f8cff\"></i>SCANNING</div>\n"
"   <div><i style=\"background:#8b5cf6\"></i>UNREADABLE QR</div>\n"
"  </div>\n"
"  <div class=\"note\">Pressing a button on the device runs the check on the ESP32 itself and\n"
"  drives this dashboard automatically. The RGB LED and buzzer mirror the status shown above.</div>\n"
" </div>\n"
"</div>\n"
"\n"
"<!-- 1 WIFI -->\n"
"<div class=\"pg\" id=\"p1\">\n"
" <div class=\"card\"><h3>Rogue Access Point Detection<em id=\"wst\">Idle</em></h3>\n"
"  <div class=\"row\" style=\"margin-bottom:16px\">\n"
"   <button onclick=\"scanWifi()\">Scan Nearby Wi-Fi</button>\n"
"   <span class=\"note\" style=\"margin:0\">Networks are ranked by security risk, safest first.</span>\n"
"  </div>\n"
"  <div class=\"tw\"><table id=\"wt\">\n"
"   <thead><tr><th>SSID</th><th>Signal</th><th>CH</th><th>Security</th>\n"
"   <th>Risk</th><th>Score</th><th>Assessment</th></tr></thead>\n"
"   <tbody><tr><td colspan=\"7\" class=\"empty\">No scan performed yet.</td></tr></tbody>\n"
"  </table></div>\n"
" </div>\n"
" <div class=\"card\"><h3>Assessment Disclaimer</h3><div class=\"disc\">\n"
"  This system provides a cybersecurity risk assessment based on observable network\n"
"  characteristics and heuristic indicators. A low-risk result does not guarantee that a\n"
"  network, URL, or QR code is completely safe, and a high-risk result does not by itself\n"
"  prove malicious intent.</div></div>\n"
"</div>\n"
"\n"
"<!-- 2 URL -->\n"
"<div class=\"pg\" id=\"p2\">\n"
" <div class=\"card\"><h3>Phishing URL Analysis<em>18 heuristic indicators</em></h3>\n"
"  <input id=\"uin\" placeholder=\"https://example.com/login\" autocomplete=\"off\"\n"
"   onkeydown=\"if(event.key==&quot;Enter&quot;)doUrl()\">\n"
"  <div class=\"row\" style=\"margin-top:11px\">\n"
"   <button onclick=\"doUrl()\">Analyse URL</button>\n"
"   <button class=\"gh sm\" onclick=\"demoUrl()\">Load a risky example</button>\n"
"  </div>\n"
"  <div id=\"ures\" style=\"margin-top:19px\"></div>\n"
" </div>\n"
"</div>\n"
"\n"
"<!-- 3 QR -->\n"
"<div class=\"pg\" id=\"p3\">\n"
" <div class=\"card\"><h3>Fake QR Code Detection<em id=\"qst\">Camera ready</em></h3>\n"
"  <div class=\"camwrap\">\n"
"   <img class=\"cam\" id=\"cam3\" alt=\"\">\n"
"   <div class=\"camoff\" id=\"off3\"><div class=\"spin\"></div><div>CONNECTING TO CAMERA</div></div>\n"
"   <div class=\"scanbox\" id=\"sbox\"><span></span><span></span><span></span><span></span>\n"
"    <div class=\"scanline\"></div></div>\n"
"  </div>\n"
"  <div class=\"row\" style=\"margin-top:14px;justify-content:center\">\n"
"   <button id=\"qb\" onclick=\"toggleQR()\">Start QR Scan</button>\n"
"   <span class=\"pill\" id=\"qfr\">0 frames</span>\n"
"  </div>\n"
"  <div id=\"qres\" style=\"margin-top:19px\"></div>\n"
"  <div class=\"note\">Hold the code about 10 to 15 cm from the lens in even light and let it fill\n"
"  the guide box. The camera switches to 640 x 480 while scanning, then returns to the live\n"
"  preview. Any link found inside the code is scored by the same engine used on the URL tab.</div>\n"
" </div>\n"
"</div>\n"
"\n"
"<!-- 4 CAMERA -->\n"
"<div class=\"pg\" id=\"p4\">\n"
" <div class=\"card\"><h3>Camera System<em id=\"cst\">Camera ready</em></h3>\n"
"  <div class=\"camwrap\">\n"
"   <img class=\"cam\" id=\"cam4\" alt=\"\">\n"
"   <div class=\"camoff\" id=\"off4\"><div class=\"spin\"></div><div>CONNECTING TO CAMERA</div></div>\n"
"  </div>\n"
"  <div class=\"row\" style=\"margin-top:14px;justify-content:center\">\n"
"   <button class=\"gh\" onclick=\"restartCam()\">Restart Preview</button>\n"
"   <span class=\"pill\" id=\"fps4\">0 FPS</span>\n"
"  </div>\n"
"  <div class=\"kv\" style=\"margin-top:16px\"><span>Preview mode</span><span id=\"cm1\">QVGA 320 x 240</span></div>\n"
"  <div class=\"kv\"><span>QR capture mode</span><span>VGA 640 x 480</span></div>\n"
"  <div class=\"kv\"><span>Transport</span><span>MJPEG stream on port 81</span></div>\n"
"  <div class=\"kv\"><span>Frames served</span><span id=\"cm2\">0</span></div>\n"
"  <div class=\"note\">Preview and QR decoding run as separate camera modes guarded by a mutex,\n"
"  so the live stream and the decoder never compete for the sensor.</div>\n"
" </div>\n"
"</div>\n"
"\n"
"<!-- 5 HISTORY -->\n"
"<div class=\"pg\" id=\"p5\">\n"
" <div class=\"card\"><h3>Threat and Event History<em>last 14 events</em></h3>\n"
"  <div class=\"tw\"><table id=\"ht\">\n"
"   <thead><tr><th>Uptime</th><th>Event</th><th>Target</th><th>Score</th><th>Risk</th></tr></thead>\n"
"   <tbody><tr><td colspan=\"5\" class=\"empty\">No events recorded yet.</td></tr></tbody>\n"
"  </table></div>\n"
" </div>\n"
"</div>\n"
"\n"
"<!-- 6 STATUS -->\n"
"<div class=\"pg\" id=\"p6\">\n"
" <div class=\"two\">\n"
"  <div class=\"card\"><h3>Device Status</h3>\n"
"   <div class=\"kv\"><span>Controller</span><span>ESP32-S3-N16R8</span></div>\n"
"   <div class=\"kv\"><span>Wi-Fi</span><span id=\"v1\">CONNECTED</span></div>\n"
"   <div class=\"kv\"><span>IP address</span><span id=\"v2\">--</span></div>\n"
"   <div class=\"kv\"><span>Camera</span><span id=\"v3\">--</span></div>\n"
"   <div class=\"kv\"><span>QR engine</span><span id=\"v4\">READY</span></div>\n"
"   <div class=\"kv\"><span>PSRAM</span><span id=\"v5\">--</span></div>\n"
"   <div class=\"kv\"><span>Free heap</span><span id=\"v6\">--</span></div>\n"
"   <div class=\"kv\"><span>Uptime</span><span id=\"v7\">--</span></div>\n"
"   <div class=\"kv\"><span>System status</span><span id=\"v8\">OPERATIONAL</span></div>\n"
"  </div>\n"
"  <div class=\"card\"><h3>Security Mode</h3>\n"
"   <div class=\"kv\"><span>Wi-Fi risk engine</span><span>LOCAL &middot; ACTIVE</span></div>\n"
"   <div class=\"kv\"><span>URL heuristic engine</span><span>LOCAL &middot; ACTIVE</span></div>\n"
"   <div class=\"kv\"><span>QR decoder</span><span>LOCAL &middot; ACTIVE</span></div>\n"
"   <div class=\"kv\"><span>RGB and buzzer alerts</span><span>ACTIVE</span></div>\n"
"   <div class=\"kv\"><span>Local dashboard</span><span>ACTIVE</span></div>\n"
"   <div class=\"kv\"><span>Online threat intelligence</span><span>NOT AVAILABLE</span></div>\n"
"   <div class=\"note\">All core security analysis runs on the device itself. An online\n"
"   reputation service can be added later as an extra verification layer without disabling\n"
"   any local function.</div>\n"
"  </div>\n"
" </div>\n"
"</div>\n"
"\n"
"<!-- 7 ABOUT -->\n"
"<div class=\"pg\" id=\"p7\">\n"
" <div class=\"card\"><h3>About the Project</h3>\n"
"  <div class=\"note\" style=\"font-size:12.5px;color:#b3c0de\">\n"
"  The Smart Portable Cybersecurity Device is an ESP32-S3 based portable security assistant\n"
"  that combines Wi-Fi risk assessment, heuristic phishing URL detection and camera based QR\n"
"  code security analysis in one embedded platform. Nearby wireless networks are evaluated\n"
"  from their observable security characteristics, URLs are scored against a multi indicator\n"
"  phishing rule engine, and QR codes are decoded from the onboard camera. When a QR code\n"
"  carries a URL it is analysed automatically by the same phishing engine. Results are shown\n"
"  on this local dashboard and signalled physically through an RGB LED and a buzzer.\n"
"  </div>\n"
"  <div class=\"disc\" style=\"margin-top:15px\">\n"
"  This system provides a cybersecurity risk assessment based on observable network\n"
"  characteristics and heuristic indicators. A low-risk result does not guarantee that a\n"
"  network, URL, or QR code is completely safe, and a high-risk result does not by itself\n"
"  prove malicious intent.</div>\n"
" </div>\n"
"</div>\n"
"\n"
"<div class=\"ft\">LOCAL ANALYSIS &middot; NO CLOUD DEPENDENCY</div>\n"
"</div>\n"
"<script src=\"https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js\"></script>\n"
"<script>\n"
"var qrRun=false, qrFrames=0, qrErrs=0, qrTimer=null, devIp=location.hostname;\n"
"var lastFrames=0, lastT=0, camLive=false;\n"
"var CAMS=[\"cam0\",\"cam3\",\"cam4\"], OFFS=[\"off0\",\"off3\",\"off4\"];\n"
"\n"
"function $(i){ return document.getElementById(i); }\n"
"\n"
"function go(i){\n"
" var t=document.querySelectorAll(\"nav div\");\n"
" for(var n=0;n<t.length;n++){ t[n].className = (n==i) ? \"on\" : \"\"; }\n"
" for(var n=0;n<8;n++){ $(\"p\"+n).className = (n==i) ? \"pg on\" : \"pg\"; }\n"
"}\n"
"\n"
"/* ---------- camera ---------- */\n"
"function showOff(txt){\n"
" camLive=false;\n"
" for(var i=0;i<OFFS.length;i++){\n"
"  var o=$(OFFS[i]);\n"
"  if(o){ o.className=\"camoff\"; o.lastChild.textContent=txt; }\n"
" }\n"
"}\n"
"function hideOff(){\n"
" camLive=true;\n"
" for(var i=0;i<OFFS.length;i++){ var o=$(OFFS[i]); if(o) o.className=\"camoff hide\"; }\n"
"}\n"
"function startStream(){\n"
" showOff(\"CONNECTING TO CAMERA\");\n"
" var u=\"http://\"+devIp+\":81/?r=\"+Date.now();\n"
" for(var i=0;i<CAMS.length;i++){\n"
"  var e=$(CAMS[i]);\n"
"  if(!e) continue;\n"
"  e.onload=hideOff;\n"
"  e.onerror=function(){ showOff(\"CAMERA NOT REACHABLE\"); };\n"
"  e.src=u;\n"
" }\n"
"}\n"
"function stopStream(){\n"
" for(var i=0;i<CAMS.length;i++){\n"
"  var e=$(CAMS[i]);\n"
"  if(e){ e.onload=null; e.onerror=null; e.removeAttribute(\"src\"); }\n"
" }\n"
"}\n"
"function restartCam(){ stopStream(); setTimeout(startStream,400); }\n"
"function setRes(){\n"
" var v=$(\"res\").value;\n"
" stopStream();\n"
" showOff(\"SWITCHING RESOLUTION\");\n"
" fetch(\"/api/cam?fs=\"+v).then(function(){ setTimeout(startStream,500); })\n"
"  .catch(function(){ setTimeout(startStream,500); });\n"
" var names={qqvga:\"QQVGA 160 x 120\",qvga:\"QVGA 320 x 240\",hvga:\"HVGA 480 x 320\",vga:\"VGA 640 x 480\"};\n"
" $(\"cm1\").innerText=names[v];\n"
"}\n"
"function setCam(mode, done){\n"
" fetch(\"/api/cam?mode=\"+mode).then(function(){ if(done) done(); })\n"
"  .catch(function(){ if(done) done(); });\n"
"}\n"
"\n"
"/* ---------- wifi ---------- */\n"
"function sig(r){\n"
" var lv = r>-55?4:(r>-65?3:(r>-75?2:1)), h=\"\";\n"
" for(var i=1;i<=4;i++){ h+=\"<i class=\\\"\"+(i<=lv?\"a\":\"\")+\"\\\" style=\\\"height:\"+(i*3+3)+\"px\\\"></i>\"; }\n"
" return \"<span class=\\\"sig\\\">\"+h+\"</span>\";\n"
"}\n"
"function scanWifi(){\n"
" $(\"wst\").innerText=\"Scanning nearby networks...\";\n"
" fetch(\"/api/wifi\").then(function(r){return r.json();}).then(function(d){\n"
"  drawWifi(d);\n"
"  $(\"wst\").innerText=d.length+\" networks detected\";\n"
"  poll();\n"
" }).catch(function(){ $(\"wst\").innerText=\"Scan failed\"; });\n"
"}\n"
"function drawWifi(d){\n"
" var tb=document.querySelector(\"#wt tbody\");\n"
" if(!d||!d.length){ tb.innerHTML=\"<tr><td colspan=\\\"7\\\" class=\\\"empty\\\">No networks detected.</td></tr>\"; return; }\n"
" d.sort(function(a,b){ return a.score-b.score; });\n"
" var h=\"\";\n"
" for(var i=0;i<d.length;i++){\n"
"  var n=d[i];\n"
"  var rec = (i==0) ? \"<b>RECOMMENDED</b> &mdash; best available option\" : n.note;\n"
"  h+=\"<tr class=\\\"\"+(i==0?\"best\":\"\")+\"\\\">\"+\n"
"     \"<td><span class=\\\"ssid\\\">\"+n.ssid+\"</span></td>\"+\n"
"     \"<td class=\\\"mono\\\">\"+sig(n.rssi)+n.rssi+\" dBm</td>\"+\n"
"     \"<td class=\\\"mono\\\">\"+n.ch+\"</td>\"+\n"
"     \"<td>\"+n.enc+\"</td>\"+\n"
"     \"<td><span class=\\\"tag t-\"+n.risk+\"\\\">\"+n.risk+\"</span></td>\"+\n"
"     \"<td class=\\\"mono\\\">\"+n.score+\"/100</td>\"+\n"
"     \"<td><div class=\\\"rec\\\">\"+rec+\"</div></td></tr>\";\n"
" }\n"
" tb.innerHTML=h;\n"
"}\n"
"\n"
"/* ---------- result rendering ---------- */\n"
"function ringHtml(score,risk){\n"
" var c = score<30?\"#22c55e\":(score<60?\"#eab308\":(score<80?\"#f97316\":\"#ef4444\"));\n"
" var deg = Math.round(score*3.6);\n"
" var txt = score<30 ? \"No strong phishing indicator was found in this target.\"\n"
"         : (score<60 ? \"Several indicators were raised. Treat this target with caution.\"\n"
"         : \"Multiple strong indicators were raised. Avoid entering any credentials.\");\n"
" return \"<div class=\\\"gauge\\\"><div class=\\\"ring\\\" style=\\\"background:conic-gradient(\"+c+\n"
"  \" \"+deg+\"deg,#16203a 0)\\\"><i><b style=\\\"color:\"+c+\"\\\">\"+score+\"</b><small>OF 100</small></i></div>\"+\n"
"  \"<div class=\\\"gmeta\\\"><h4 style=\\\"color:\"+c+\"\\\">\"+risk+\"</h4><p>\"+txt+\"</p></div></div>\";\n"
"}\n"
"function render(d){\n"
" if(!d||!d.items) return \"<div class=\\\"empty\\\">No result.</div>\";\n"
" var bad=0;\n"
" for(var i=0;i<d.items.length;i++){ if(d.items[i].b) bad++; }\n"
" var h=\"<div class=\\\"kv\\\"><span>Target</span><span>\"+d.url+\"</span></div>\"+\n"
"       \"<div class=\\\"kv\\\"><span>Content type</span><span>\"+d.type+\"</span></div>\"+\n"
"       \"<div class=\\\"kv\\\"><span>Indicators raised</span><span>\"+bad+\" of \"+d.items.length+\"</span></div>\"+\n"
"       \"<div style=\\\"margin-top:16px\\\">\"+ringHtml(d.score,d.risk)+\"</div><ul class=\\\"vlist\\\">\";\n"
" for(var i=0;i<d.items.length;i++){\n"
"  h+=\"<li class=\\\"\"+(d.items[i].b?\"b\":\"\")+\"\\\"><em>\"+d.items[i].n+\"</em><span>\"+d.items[i].s+\"</span></li>\";\n"
" }\n"
" return h+\"</ul>\";\n"
"}\n"
"function doUrl(){\n"
" var u=$(\"uin\").value.trim();\n"
" if(!u) return;\n"
" $(\"ures\").innerHTML=\"<div class=\\\"empty\\\">Analysing...</div>\";\n"
" fetch(\"/api/url?u=\"+encodeURIComponent(u))\n"
"  .then(function(r){ return r.json(); })\n"
"  .then(function(d){ $(\"ures\").innerHTML=render(d); poll(); });\n"
"}\n"
"function demoUrl(){\n"
" $(\"uin\").value=\"http://secure-paypa1-verify.account-update.xyz/login?token=1\";\n"
" doUrl();\n"
"}\n"
"\n"
"/* ---------- QR ---------- */\n"
"function toggleQR(){\n"
" qrRun=!qrRun;\n"
" $(\"qb\").innerText = qrRun ? \"Stop QR Scan\" : \"Start QR Scan\";\n"
" if(qrRun){\n"
"  qrFrames=0; qrErrs=0;\n"
"  $(\"qres\").innerHTML=\"\";\n"
"  $(\"qfr\").innerText=\"0 frames\";\n"
"  $(\"sbox\").className=\"scanbox on\";\n"
"  stopStream();\n"
"  showOff(\"SWITCHING TO QR MODE\");\n"
"  $(\"qst\").innerText=\"Starting camera\";\n"
"  setCam(\"qr\", function(){\n"
"   $(\"qst\").innerText=\"Scanning for a QR code\";\n"
"   setTimeout(qrTick,200);\n"
"  });\n"
"  clearTimeout(qrTimer);\n"
"  qrTimer=setTimeout(function(){\n"
"   if(qrRun){\n"
"    qrRun=false;\n"
"    $(\"qb\").innerText=\"Start QR Scan\";\n"
"    $(\"qst\").innerText=\"No QR code detected\";\n"
"    $(\"sbox\").className=\"scanbox\";\n"
"    setCam(\"preview\", startStream);\n"
"   }\n"
"  },45000);\n"
" } else {\n"
"  clearTimeout(qrTimer);\n"
"  $(\"sbox\").className=\"scanbox\";\n"
"  $(\"qst\").innerText=\"Camera ready\";\n"
"  setCam(\"preview\", startStream);\n"
" }\n"
"}\n"
"function qrTick(){\n"
" if(!qrRun) return;\n"
" var im=new Image();\n"
" im.onload=function(){\n"
"  if(!qrRun) return;\n"
"  hideOff();\n"
"  var e=$(\"cam3\");\n"
"  if(e) e.src=im.src;\n"
"  var c=$(\"cv\") || (function(){\n"
"    var n=document.createElement(\"canvas\"); n.id=\"cv\"; n.style.display=\"none\";\n"
"    document.body.appendChild(n); return n; })();\n"
"  c.width=im.width; c.height=im.height;\n"
"  var x=c.getContext(\"2d\",{willReadFrequently:true});\n"
"  x.drawImage(im,0,0);\n"
"  qrFrames++;\n"
"  $(\"qfr\").innerText=qrFrames+\" frames\";\n"
"  var q=null, bad=null;\n"
"  try{\n"
"   var d=x.getImageData(0,0,c.width,c.height);\n"
"   q=jsQR(d.data,c.width,c.height,{inversionAttempts:\"attemptBoth\"});\n"
"  }catch(ex){ bad=ex; }\n"
"  if(bad){\n"
"   qrRun=false;\n"
"   $(\"qb\").innerText=\"Start QR Scan\";\n"
"   $(\"qst\").innerText=\"Decoder blocked - reload the page\";\n"
"   $(\"sbox\").className=\"scanbox\";\n"
"   setCam(\"preview\", startStream);\n"
"   return;\n"
"  }\n"
"  if(q && q.data){\n"
"   qrRun=false;\n"
"   clearTimeout(qrTimer);\n"
"   $(\"qb\").innerText=\"Start QR Scan\";\n"
"   $(\"qst\").innerText=\"QR code detected\";\n"
"   $(\"sbox\").className=\"scanbox\";\n"
"   fetch(\"/api/url?qr=1&u=\"+encodeURIComponent(q.data))\n"
"    .then(function(r){ return r.json(); })\n"
"    .then(function(d2){\n"
"      $(\"qres\").innerHTML=render(d2);\n"
"      setCam(\"preview\", startStream);\n"
"      poll();\n"
"    });\n"
"  } else {\n"
"   setTimeout(qrTick,30);\n"
"  }\n"
" };\n"
" im.onerror=function(){\n"
"  if(!qrRun) return;\n"
"  qrErrs++;\n"
"  if(qrErrs==6){ $(\"qst\").innerText=\"Camera not responding - retrying\"; }\n"
"  if(qrErrs>=25){\n"
"   qrRun=false; clearTimeout(qrTimer);\n"
"   $(\"qb\").innerText=\"Start QR Scan\";\n"
"   $(\"qst\").innerText=\"Camera capture failed - check Serial Monitor\";\n"
"   $(\"sbox\").className=\"scanbox\";\n"
"   setCam(\"preview\", startStream);\n"
"   return;\n"
"  }\n"
"  setTimeout(qrTick,200);\n"
" };\n"
" im.src=\"/snap?t=\"+Date.now();\n"
"}\n"
"\n"
"/* ---------- history ---------- */\n"
"function drawHist(h){\n"
" var tb=document.querySelector(\"#ht tbody\");\n"
" if(!h||!h.length){ tb.innerHTML=\"<tr><td colspan=\\\"5\\\" class=\\\"empty\\\">No events recorded yet.</td></tr>\"; return; }\n"
" var s=\"\";\n"
" for(var i=h.length-1;i>=0;i--){\n"
"  var cl = h[i].score<30 ? \"t-ok\" : (h[i].score<60 ? \"t-wn\" : \"t-bad\");\n"
"  s+=\"<tr><td class=\\\"mono\\\">\"+h[i].t+\"s</td><td>\"+h[i].e+\n"
"     \"</td><td class=\\\"rec\\\">\"+h[i].g+\"</td><td class=\\\"mono\\\">\"+h[i].score+\n"
"     \"/100</td><td><span class=\\\"tag \"+cl+\"\\\">\"+h[i].r+\"</span></td></tr>\";\n"
" }\n"
" tb.innerHTML=s;\n"
"}\n"
"\n"
"/* ---------- status poll ---------- */\n"
"function poll(){\n"
" fetch(\"/api/status\").then(function(r){ return r.json(); }).then(function(s){\n"
"  devIp=s.ip;\n"
"  $(\"led\").className=\"led \"+s.led;\n"
"  $(\"stv\").innerText=s.status;\n"
"  $(\"ls\").innerText=s.status;\n"
"  $(\"pIp\").innerText=s.ip;\n"
"  $(\"pCam\").innerText=s.cam;\n"
"  $(\"pUp\").innerText=s.up+\"s\";\n"
"  $(\"cst\").innerText=s.cam;\n"
"  $(\"v1\").innerText=\"CONNECTED\";\n"
"  $(\"v2\").innerText=s.ip;\n"
"  $(\"v3\").innerText=s.cam;\n"
"  $(\"v5\").innerText=s.psram?\"AVAILABLE\":\"UNAVAILABLE\";\n"
"  $(\"v6\").innerText=s.heap+\" bytes\";\n"
"  $(\"v7\").innerText=s.up+\" seconds\";\n"
"  $(\"cm2\").innerText=s.frames;\n"
"  $(\"k1\").innerText=s.scans;\n"
"  $(\"k2\").innerText=s.nets;\n"
"  $(\"k3\").innerText=s.urls;\n"
"  $(\"k4\").innerText=s.qrs;\n"
"  $(\"k5\").innerText=s.threats;\n"
"  $(\"lw\").innerText = s.scans ? s.best : \"no scan yet\";\n"
"\n"
"  var c = s.score<30?\"#22c55e\":(s.score<60?\"#eab308\":(s.score<80?\"#f97316\":\"#ef4444\"));\n"
"  $(\"mtr\").style.width=Math.min(100,s.score)+\"%\";\n"
"  $(\"mtr\").style.background=c;\n"
"  $(\"mval\").innerText=s.score+\"/100\";\n"
"  $(\"mval\").style.color=c;\n"
"  $(\"stsub\").innerText = s.scans+s.urls+s.qrs ? \"Last assessment scored \"+s.score+\" of 100\"\n"
"                                              : \"Awaiting a security scan\";\n"
"\n"
"  var now=Date.now();\n"
"  if(lastT){\n"
"   var f=Math.max(0,(s.frames-lastFrames)*1000/(now-lastT));\n"
"   var txt=f.toFixed(1)+\" FPS\";\n"
"   $(\"pFps\").innerText=txt; $(\"fps4\").innerText=txt; $(\"fps0\").innerText=f.toFixed(1)+\" fps\";\n"
"  }\n"
"  lastFrames=s.frames; lastT=now;\n"
"\n"
"  drawHist(s.hist);\n"
"  if(s.hist && s.hist.length){\n"
"   var last=s.hist[s.hist.length-1];\n"
"   $(\"le\").innerText=last.e+\" - \"+last.r;\n"
"   for(var i=s.hist.length-1;i>=0;i--){\n"
"    if(s.hist[i].e==\"URL SCAN\"){ $(\"lu\").innerText=s.hist[i].r+\" (\"+s.hist[i].score+\"/100)\"; break; }\n"
"   }\n"
"   for(var i=s.hist.length-1;i>=0;i--){\n"
"    if(s.hist[i].e==\"QR CODE\"){ $(\"lq\").innerText=s.hist[i].r+\" (\"+s.hist[i].score+\"/100)\"; break; }\n"
"   }\n"
"  }\n"
"  if(s.wifiReq){ go(1); fetch(\"/api/last\").then(function(r){return r.json();})\n"
"    .then(function(d){ drawWifi(d.wifi); $(\"wst\").innerText=d.wifi.length+\" networks detected\"; }); }\n"
"  if(s.urlReq){ go(2); $(\"uin\").focus(); }\n"
"  if(s.qrReq && !qrRun){ go(3); toggleQR(); }\n"
" }).catch(function(){});\n"
"}\n"
"\n"
"window.addEventListener(\"load\", function(){\n"
" fetch(\"/api/status\").then(function(r){ return r.json(); }).then(function(s){\n"
"  devIp=s.ip;\n"
"  startStream();\n"
" }).catch(function(){ startStream(); });\n"
" setInterval(poll,1500);\n"
" poll();\n"
"});\n"
"</script></body></html>\n"
;

// ================= HTTP HANDLERS =================
void handleRoot() { server.send_P(200, "text/html", PAGE); }

void handleApiWifi() {
  runWiFiScan();
  server.send(200, "application/json", wifiJson);
}

void handleApiUrl() {
  String u = server.arg("u");
  bool fromQR = server.arg("qr") == "1";
  if (u.length() == 0) { server.send(400, "application/json", "{}"); return; }
  runURLCheck(u, fromQR);
  server.send(200, "application/json", fromQR ? qrJson : urlJson);
}

void handleApiLast() {
  String j = "{\"wifi\":" + wifiJson + ",\"url\":" + urlJson + ",\"qr\":" + qrJson + "}";
  server.send(200, "application/json", j);
}

void handleApiStatus() {
  String j = "{";
  j += "\"status\":\"" + secStatus + "\",";
  j += "\"led\":\"" + ledState + "\",";
  j += "\"cam\":\"" + camState + "\",";
  j += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  j += "\"score\":" + String(curScore) + ",";
  j += "\"scans\":" + String(scanCount) + ",";
  j += "\"nets\":" + String(netCount) + ",";
  j += "\"urls\":" + String(urlCount) + ",";
  j += "\"qrs\":" + String(qrCount) + ",";
  j += "\"threats\":" + String(threatCount) + ",";
  j += "\"best\":\"" + jesc(bestSSID) + "\",";
  j += "\"psram\":" + String(psramFound() ? "true" : "false") + ",";
  j += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
  j += "\"frames\":" + String((unsigned long)streamFrames) + ",";
  j += "\"stream\":" + String(streamOn ? "true" : "false") + ",";
  j += "\"up\":" + String((millis() - bootTime) / 1000) + ",";
  j += "\"wifiReq\":" + String(wifiRequest ? "true" : "false") + ",";
  j += "\"urlReq\":" + String(urlRequest ? "true" : "false") + ",";
  j += "\"qrReq\":" + String(qrRequest ? "true" : "false") + ",";
  j += "\"hist\":[";
  for (int i = 0; i < histCount; i++) {
    if (i) j += ",";
    j += "{\"t\":" + String(histTime[i]) + ",\"e\":\"" + jesc(histType[i]) +
         "\",\"g\":\"" + jesc(histTarget[i]) + "\",\"score\":" + String(histScore[i]) +
         ",\"r\":\"" + histRisk[i] + "\"}";
  }
  j += "]}";
  wifiRequest = false;
  urlRequest = false;
  qrRequest = false;
  server.send(200, "application/json", j);
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  delay(600);
  bootTime = millis();
  Serial.println("\n=== SENTINEL : Smart Portable Cybersecurity Device ===");

  pinMode(BTN_WIFI, INPUT_PULLUP);
  pinMode(BTN_URL,  INPUT_PULLUP);
  pinMode(BTN_QR,   INPUT_PULLUP);
  pinMode(BUZZER, OUTPUT);
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  digitalWrite(BUZZER, LOW);
  ledOff();

  camMutex = xSemaphoreCreateMutex();

  Serial.println(psramFound() ? "PSRAM: available" : "PSRAM: NOT found - enable OPI PSRAM");
  cameraOK = startCamera();
  Serial.println(cameraOK ? "Camera: ready" : "Camera: FAILED");

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to Wi-Fi");
  int t = 0;
  while (WiFi.status() != WL_CONNECTED && t < 40) {
    delay(500); Serial.print("."); t++;
    setColor(0, 0, (t % 2));
  }
  ledOff();
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("-----------------------------------------");
    Serial.print("  DASHBOARD:  http://");
    Serial.println(WiFi.localIP());
    Serial.println("-----------------------------------------");
  } else {
    Serial.println("Wi-Fi failed. Check SSID and password, 2.4GHz only.");
  }

  server.on("/", handleRoot);
  server.on("/api/wifi", handleApiWifi);
  server.on("/api/url", handleApiUrl);
  server.on("/api/status", handleApiStatus);
  server.on("/api/last", handleApiLast);
  server.on("/snap", handleSnap);
  server.on("/api/cam", handleCamMode);
  server.begin();

  if (cameraOK) {
    xTaskCreatePinnedToCore(streamTask, "stream", 5120, NULL, 1, NULL, 0);
  }

  addEvent("SYSTEM", "device started", 0, "LOW RISK");
  ledGreen(); delay(400); ledOff();
  beep(1, 100);
  Serial.println("System ready.");
}

// ================= LOOP =================
void loop() {
  server.handleClient();

  if (digitalRead(BTN_WIFI) == LOW) {
    delay(45);
    if (digitalRead(BTN_WIFI) == LOW) {
      runWiFiScan();
      wifiRequest = true;
      while (digitalRead(BTN_WIFI) == LOW) delay(10);
    }
  }

  if (digitalRead(BTN_URL) == LOW) {
    delay(45);
    if (digitalRead(BTN_URL) == LOW) {
      urlRequest = true;
      ledBlue();
      secStatus = "AWAITING URL";
      Serial.println("URL mode - enter a link on the dashboard.");
      beep(1, 60);
      while (digitalRead(BTN_URL) == LOW) delay(10);
    }
  }

  if (digitalRead(BTN_QR) == LOW) {
    delay(45);
    if (digitalRead(BTN_QR) == LOW) {
      qrRequest = true;
      ledBlue();
      camState = "QR SCANNING";
      secStatus = "QR SCAN MODE";
      Serial.println("QR mode - dashboard starts the decoder.");
      beep(1, 60);
      while (digitalRead(BTN_QR) == LOW) delay(10);
    }
  }

  delay(4);
}
