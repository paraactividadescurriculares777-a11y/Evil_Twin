# Evil Twin APSTA — Repetidor MITM (ESP32)

Proyecto académico de seguridad para la **Sociedad Científica – UMSS San Simón**.
Demuestra un ataque *Evil Twin* completo con enrutamiento real (repetidor MITM) sobre un
ESP32, portal cautivo, captura de credenciales y una pantalla OLED de estado.

> ⚠️ **Solo con fines educativos y sobre tu propia red.** Usar esto contra redes o
> personas sin autorización es ilegal.

## ¿Qué hace?

1. El ESP32 se conecta a una red WiFi real como cliente (STA).
2. Crea una red falsa (AP) — `MOVISTAR_Guest` — en el **mismo canal** que la real.
3. Activa **NAT (NAPT)** para enrutar el tráfico del AP falso hacia Internet real.
4. **DNS en dos fases:**
   - *Portal:* secuestra el DNS → salta el portal cautivo → captura credenciales.
   - *Internet:* tras capturar, resuelve dominios reales → la víctima navega (MITM completo).
5. **OLED SH1106 128x64** con 3 pantallas rotativas (estado MITM / red real / escaneo WiFi)
   y una alerta grande al capturar una credencial.

## Hardware

- ESP32 DevKit (probado con ESP32-D0WD-V3).
- Pantalla OLED **SH1106** 128x64 por I2C (SDA=21, SCL=22, dir 0x3C).
- LED RGB (pines 5/18/19), buzzer (pin 4).

## Configuración de credenciales

Las credenciales de tu red real **no** están en el repo. Antes de compilar:

```bash
cd Evil_Twin_APSTA_NoBlock
cp credenciales_wifi.ejemplo.h credenciales_wifi.h
# edita credenciales_wifi.h con el nombre y clave de TU red
```

`credenciales_wifi.h` está en `.gitignore`, así que tu clave se queda local.

## Compilar y flashear (arduino-cli)

Requiere el core **esp32 3.3.10** (trae NAPT compilado) y **modo de flash DIO**:

```bash
FQBN="esp32:esp32:esp32:FlashMode=dio,FlashFreq=40"
arduino-cli compile --fqbn "$FQBN" Evil_Twin_APSTA_NoBlock/Evil_Twin_APSTA_NoBlock.ino
arduino-cli upload -p /dev/ttyUSB0 --fqbn "$FQBN" Evil_Twin_APSTA_NoBlock/Evil_Twin_APSTA_NoBlock.ino
```

### Notas de la placa (aprendidas a la mala)
- **Modo DIO obligatorio**: con QIO esta placa entra en boot-loop (`invalid header`).
- **NAPT**: el core 3.3.10 usa *TCPIP core-locking* (IDF 5.x); hay que envolver
  `ip_napt_enable()` con `LOCK_TCPIP_CORE()` / `UNLOCK_TCPIP_CORE()`.
- **Canal AP=STA**: el ESP32 tiene una sola radio; el AP falso debe arrancar en el
  mismo canal que la red real o tira a los clientes al saltar de canal.
- **OLED**: es un **SH1106** (no SSD1306); usa la librería `Adafruit_SH110X`.

## Opciones

En el `.ino`:

```c
#define ABRIR_INTERNET_AL_INICIO  false  // false = portal salta al entrar (demo)
                                         // true  = internet directo (repetidor puro)
```

## Estructura

```
Evil_Twin_APSTA_NoBlock/     sketch principal (Arduino IDE / arduino-cli)
  Evil_Twin_APSTA_NoBlock.ino
  credenciales_wifi.ejemplo.h  plantilla (se sube)
  credenciales_wifi.h          tus credenciales (NO se sube)
src/                          copia para PlatformIO
platformio.ini
sdkconfig.defaults
```
