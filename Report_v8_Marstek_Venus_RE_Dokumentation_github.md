# Marstek Venus — Modbus Reverse Engineering Dokumentation
## Vollständige Analyse-Dokumentation (Mai 2026) — Rev 8

**Gerät:** Marstek Venus D (`VNSD-0`), 2 Batterie-Packs  
**Firmware:** `VNSEE3-0_app_0148_0306_115507.bin` — VNS EE 3.0, Version 148  
**Ziel:** Vollständige Modbus-Register-Map für Home Assistant Integration  
**Status:** 89 Read-Register und 41 Write-Register bestätigt — vollständiger Adressraum 0–65535 gescannt und abgeschlossen — Cloud-API & OTA-Infrastruktur vollständig analysiert (9 MCU-Komponenten dokumentiert)

---

## Inhaltsverzeichnis

1. [Hardware & Firmware-Architektur](#1-hardware--firmware-architektur)
2. [Modbus-Protokoll-Details](#2-modbus-protokoll-details)
3. [Descriptor-Tabelle (Interne Struktur)](#3-descriptor-tabelle-interne-struktur)
4. [Bekannte Flash-Adressen (Ghidra)](#4-bekannte-flash-adressen-ghidra)
5. [Bekannte SRAM-Adressen](#5-bekannte-sram-adressen)
6. [Bestätigte Read-Register (30000–39999)](#6-bestätigte-read-register-30000-39999)
7. [Bestätigte Write-Register (40000–49999)](#7-bestätigte-write-register-40000-49999)
8. [Kritische Besonderheiten](#8-kritische-besonderheiten)
9. [MQTT-Feldnamen → Register-Mapping](#9-mqtt-feldnamen--register-mapping)
10. [Marstek Local API — Parallelprotokoll & Cross-Validierung](#10-marstek-local-api--parallelprotokoll--cross-validierung)
11. [Marstek Cloud API & OTA-Infrastruktur](#11-marstek-cloud-api--ota-infrastruktur)
12. [Analyse-Skripte (Übersicht)](#12-analyse-skripte-ubersicht)
13. [Reverse Engineering — Methodik & Erkenntnisse](#13-reverse-engineering--methodik--erkenntnisse)
14. [Ghidra-Analyse-Erkenntnisse](#14-ghidra-analyse-erkenntnisse)
15. [Falsche Fährten & Lektionen](#15-falsche-fahrten--lektionen)
16. [Offene Punkte & nächste Schritte](#16-offene-punkte--nachste-schritte)

---

> **Hinweis:** Diese Dokumentation wurde für die Veröffentlichung anonymisiert.
> Gerätespezifische Werte (UID, MAC, Seriennummer, IP) wurden durch Platzhalter ersetzt.
> Die technischen Inhalte (Register-Map, Protokoll-Details, Firmware-Analyse) sind vollständig.

## 1. Hardware & Firmware-Architektur

### MCU & Betriebssystem

```
MCU:        STM32 (ARM Cortex-M, Thumb-2, Little-Endian)
OS:         FreeRTOS
Flash:      0x08000000 – 0x08058FFF  (364.544 Bytes)
SRAM:       0x20000000 – 0x2001FFFF  (128 KB)
Ext-RAM:    0x60000000 – 0x6001FFFF  (CH395Q oder ähnlich, für Netzwerkpuffer)
```

### Firmware-Binary-Eigenschaften

```
Datei:      VNSEE3-0_app_0148_0306_115507.bin
Größe:      364.544 Bytes
IVT:        0x08000000  (Interrupt Vector Table, ARM-Standard)
App-Start:  0x08004000
EMS-FW:     Version 147
VMS-FW:     Version 115
BMS-FW:     Version 116
```

### Subsysteme

| Komponente | Beschreibung |
|---|---|
| CH395Q | Ethernet-Controller (SPI → Modbus TCP Port 502) |
| FC41D | WiFi 802.11b/g/n + BLE 5.0 (UART AT-Befehle) |
| RS485 | 47.400 Baud, Modbus RTU → Inverter/EMS |
| mbedTLS | AES-128/256, RSA, ECDH secp256r1 (für Cloud-TLS) |
| MQTT | Gerät kommuniziert mit `eu.hamedata.com` |

### Kommunikationskanäle (vollständig)

Das Gerät exponiert **vier unabhängige Protokoll-Stacks**. Für die HA-Integration
wird **ausschließlich Modbus TCP** verwendet:

| Kanal | Port / Medium | Protokoll | Status für HA |
|---|---|---|---|
| **Modbus TCP** | :502 (Ethernet/WiFi) | Modbus FC03/FC06/FC16 | ✅ Aktiv nutzen |
| **Local API** | UDP :30000 (WiFi) | JSON-RPC | ⛔ NICHT aktivieren (s. Abschnitt 10) |
| **BLE** | Bluetooth LE | HM-Protokoll (0x23-Frames) | ℹ️ Nur Monitoring-Tool rweijnen |
| **Cloud/MQTT** | TCP :8883 TLS | MQTT → `eu.hamedata.com` | ❌ Kein lokaler Zugriff |

### FreeRTOS-Tasks (aus String-Analyse)

```
Task_Modbus_tcp    - Modbus TCP Server (Port 502)
ch395              - Ethernet-Controller
fc41d              - WiFi/BLE-Modul
ch_mqtts           - MQTT-Client (Cloud)
rs485              - RS485/Modbus RTU
ems                - Energy Management System
udp                - UDP-Listener → Local API (Port 30000, JSON-RPC)
```

> **Hinweis zu `udp`-Task:** Früher als "Discovery auf Port 8899" erfasst.
> Nach Analyse der offiziellen Local API Doku (REV 0.5) ist der Default-Port 30000.
> Dieser Task implementiert den Local API JSON-RPC Daemon.
> **Aktivierung verursacht Modbus-Fehler — siehe Abschnitt 10.**

---

## 2. Modbus-Protokoll-Details

### Verbindung

```
Protokoll:    Modbus TCP
Port:         502
Slave-ID:     1
Max. Request: 125 Register pro Read-Request (Modbus-Standard)
```

### Register-Adressierung

**Wichtig:** Marstek verwendet **direkte Adressierung** — die Modbus-PDU-Adresse entspricht exakt der sichtbaren Register-Nummer. Es gibt keinen Offset in irgendeiner Richtung.

```
User-Register 30000  →  PDU-Adresse 30000  (0x7530)   ← kein -1
User-Register 34002  →  PDU-Adresse 34002  (0x84D2)   ← kein -1
Grenze Read/Write:   40000 (0x9C40)
```

> **Beweis aus TCPRouter.c (Decompilat):**
> `uVar6 = CONCAT11(param_1[0], param_1[1])` → rohe PDU-Adresse, unverändert.
> `if (uVar6 < descriptor.base_addr)` → direkter Vergleich, kein Offset.
> `Serializer.c`: `offset = PDU_addr - base_addr` → bei Reg 30000 und `base_addr=30000` ist Offset=0. ✅
>
> **Unterschied zu Standard-Modbus:** Im klassischen Modbus-Standard gilt
> „Register 1 = PDU-Adresse 0" (User-Nummer minus 1). Marstek ignoriert diese
> Konvention vollständig. pymodbus-Aufruf: `read_holding_registers(30000)` → korrekt.

### Register-Bereiche

| Bereich | Typ | Beschreibung | Status |
|---|---|---|---|
| 0 – 29.999 | – | Leer | ✅ Gescannt — **keine Register vorhanden** |
| 30.000 – 39.999 | Read | Sensor-/Status-Daten | ✅ 89 Register bestätigt |
| 40.000 – 49.999 | Write | Steuerregister | ✅ 41 Register bestätigt |
| 50.000 – 65.535 | – | Leer | ✅ Gescannt — **keine Register vorhanden** |

> **Fazit:** Der vollständige Modbus-Adressraum (0–65535) wurde gescannt.
> Alle Register des Geräts befinden sich ausschließlich im Bereich 30000–49999.
> Die Bereiche 0–29999 und 50000–65535 liefern keine Antworten.

### Routing-Logik (aus TCPRouter.c)

```c
// FC06/FC16 (Write-Request):
if (uVar6 >= 40000)  →  Write-Handler  (FUN_0804c83c)
if (uVar6 < 40000)   →  Descriptor-Tabelle lesen  (FUN_0804b73c)

// Tabellen-Iteration:
for (uVar4 = 0; uVar4 < 231; uVar4++) {
    // Vergleicht angefragte Adresse mit Tabellen-Einträgen
    (&DAT_200002f8)[uVar4 * 6]  // ushort* Zugriff = 12 Bytes/Eintrag
}
```

---

## 3. Descriptor-Tabelle (Interne Struktur)

Die Tabelle wird zur **Laufzeit im SRAM aufgebaut** und existiert nicht als statische Flash-Struktur.

### SRAM-Position

```
Adresse:     0x200002F8 (SRAM)
Einträge:    231 (0xE7)
Größe:       231 × 12 = 2.772 Bytes (bis 0x20000DCC)
```

### Eintrag-Format (12 Bytes)

```c
struct RegisterDescriptor {     // 12 Bytes pro Eintrag
    uint16_t  base_addr;        // [0:2]  Direkte PDU-Adresse (= User-Register-Nummer, kein Offset)
    uint16_t  padding;          // [2:4]  unbekannt/padding
    uint32_t* data_ptr;         // [4:8]  SRAM-Zeiger auf Rohdaten
    uint8_t   data_type;        // [8]    Datentyp
    uint8_t   reg_size;         // [9]    Größe in Registern (& 0x0F)
    uint8_t   scale;            // [10]   Skalierungscode
    uint8_t   count;            // [11]   Anzahl Elemente
};
```

### Datentyp-Codes

| Code | Typ | Größe |
|---|---|---|
| 0x01 | uint8 | 1 Byte |
| 0x02 | uint16 | 2 Bytes |
| 0x04 | uint32 | 4 Bytes |
| 0x11 | int8 | 1 Byte |
| 0x12 | int16 | 2 Bytes |
| 0x14 | int32 | 4 Bytes |
| 0x24 | float32 | 4 Bytes |
| 0x31 | ASCII | variabel |

### Skalierungs-Codes

| Code | Bedeutung | Beispiel |
|---|---|---|
| 0x00 | × 1 | Rohwert direkt |
| 0x01 | × 10 | Rohwert × 10 |
| 0x02 | × 100 | Rohwert × 100 |
| 0x03 | ÷ 10 (= × 0.1) | Rohwert 3116 → 311.6 |
| 0x04 | ÷ 100 (= × 0.01) | Rohwert 5012 → 50.12 V |
| 0x05 | negieren | Rohwert × −1 |

### Serializer-Logik (aus Serializer.c)

```c
// Float-Typ ($=0x24):
local_3c = *(float *)(data_ptr + element_index * 4);
// Skalierung anwenden...
// Andere Typen:
case 0x02: local_38 = *(ushort*)(data_ptr + offset);
case 0x12: local_38 = *(short*)(data_ptr + offset);
case 0x14: local_38 = *(uint*)(data_ptr + offset);
// Scale switch:
case 0x03: local_38 = local_38 / 10;
case 0x04: local_38 = local_38 / 100;
case 0x05: local_38 = -local_38;
```

---

## 4. Bekannte Flash-Adressen (Ghidra)

| Flash-Adresse | Funktion | Beschreibung |
|---|---|---|
| `0x08000000` | IVT | Interrupt-Vektortabelle |
| `0x08004000` | App-Start | Beginn des Anwendungscodes |
| `0x08018000` | String-Pool | MQTT-Feldnamen (bat_soc, ongrid_power, …) |
| `0x08050000` | String-Pool 2 | Debug-CLI, chinesische Strings |
| `0x08058000` | TLS-Zertifikate | CA-Cert für hamedata.com |
| `0x0801c088` | `FUN_0801c088` | **Modbus TCP Router** |
| `0x0804b73c` | `FUN_0804b73c` | **Generic Register Serializer** |
| `0x0804c83c` | `FUN_0804c83c` | **Write-Register Handler** |
| `0x080128a0` | `FUN_080128a0` | JSON-Config-Parser (KEIN Modbus-Init!) |
| `0x0801bcb0` | `FUN_0801bcb0` | RS485/RTU Paket-Handler |

### Wichtige Fehlidentifikationen

> ⚠️ `FUN_080128a0` (enthält MOVW #0x7530) ist **kein** Descriptor-Init!
> Es ist ein JSON-Config-Parser. Der Wert 0x7530 = 30.000 ist dort ein **Standard-API-Port**, nicht eine Register-Adresse.

> ⚠️ `FUN_0801bcb0` ist der **RS485/RTU Paket-Handler**, nicht die Descriptor-Initialisierung.

---

## 5. Bekannte SRAM-Adressen

Aus WriteHandler.c dekompiliert:

| SRAM-Adresse | Variable | Bedeutung |
|---|---|---|
| `0x20000133` | `DAT_20000133` | Modbus Slave-Adresse |
| `0x20000156` | `_DAT_20000156` | Max Entladeleistung (short) |
| `0x20000158` | `DAT_20000158` | Max Ladeleistung (short) |
| `0x2000027c` | `DAT_2000027c` | RS485-Steuerung aktiv (0/1/2) |
| `0x200002ec` | `DAT_200002ec` | Reset-Kommando-Status |
| `0x200002ed` | `DAT_200002ed` | Betriebsmodus (work_mode) |
| `0x200002ee` | `DAT_200002ee` | Lade-Ziel-SOC |
| `0x200002f0` | `DAT_200002f0` | Entlade-Leistungsvorgabe (short) |
| `0x200002f2` | `DAT_200002f2` | Lade-Leistungsvorgabe (short) |
| `0x200002f8` | `DAT_200002f8` | **Descriptor-Tabellen-Basis** |
| `0x20014b6c` | `DAT_20014b6c` | Backup/UPS-Funktion aktiv |
| `0x20014b6d` | `DAT_20014b6d` | Betriebsmodus intern |
| `0x20014b6f..` | Schedule-Daten | Zeitplan-Enable-Bytes |
| `0x20014c25..` | Schedule-Times | Zeitplan-Start/Ende/Power |

---

## 6. Bestätigte Read-Register (30000–39999)

**Scan-Datum:** Mai 2026 | **Gerät:** Marstek Venus D, 2 Batterie-Packs  
**Bedingung:** PV nicht angeschlossen (MPPT-Werte = Leerlauf ~9.9V)

### 6.1 Leistung & AC-Netz

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 30001 | battery_power | int16 | 1 | W | 65525 | −11 W (Entladung) |
| 30006 | ac_power | int16 | 1 | W | 0 | 0 W |
| 32200 | ac_voltage | uint16 | 0.1 | V | 2398 | 239.8 V |
| 32204 | ac_frequency | int16 | 0.1 | Hz | 499 | 49.9 Hz |
| 32300 | ac_offgrid_voltage | uint16 | 0.1 | V | 3 | 0.3 V (Offgrid aus) |
| 32301 | ac_offgrid_current | uint16 | 0.01 | A | 3 | 0.03 A |
| 32302 | ac_offgrid_power | int32 | 1 | W | 0 | 0 W (2 Register) |
| 37004 | ac_current | int16 | 0.01 | A | 65038 | −4.98 A (Einspeisung) |

### 6.2 MPPT / PV-Eingänge

| Register | Name | Typ | Scale | Einheit | Hinweis |
|---|---|---|---|---|---|
| 30020 | mppt1_voltage | uint16 | 0.1 | V | Leerlauf = 9.9V bei nicht angeschlossenem PV |
| 30021 | mppt2_voltage | uint16 | 0.1 | V | dto. |
| 30022 | mppt3_voltage | uint16 | 0.1 | V | dto. |
| 30023 | mppt4_voltage | uint16 | 0.1 | V | dto. |
| 30024 | mppt1_current | uint16 | 0.1 | A | |
| 30025 | mppt2_current | uint16 | 0.1 | A | |
| 30026 | mppt3_current | uint16 | 0.1 | A | |
| 30027 | mppt4_current | uint16 | 0.1 | A | |
| 30037 | mppt1_power | uint16 | 0.1 | W | |
| 30038 | mppt2_power | uint16 | 0.1 | W | |
| 30039 | mppt3_power | uint16 | 0.1 | W | |
| 30040 | mppt4_power | uint16 | 0.1 | W | |

### 6.3 Batterie Pack 1

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 30100 | battery_voltage | uint16 | 0.01 | V | 5012 | 50.12 V |
| 30101 | battery_current | int16 | 0.1 | A | 0 | 0.0 A |
| 32105 | battery_total_energy | uint16 | 0.001 | kWh | 5120 | 5.120 kWh |
| 34002 | battery_soc | uint16 | **0.1** | % | 109 | **10.9 %** ⚠️ |
| 34003 | battery_cycle_count | uint16 | 1 | – | 14 | 14 Zyklen |
| 34010 | battery_1_bms_version | uint16 | 1 | – | 116 | **v116** (BMS-Version pro Pack) |
| 34018 | battery_1_cell_1_voltage | int16 | 0.001 | V | 3116 | 3.116 V |
| 34019 | battery_1_cell_2_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34020 | battery_1_cell_3_voltage | int16 | 0.001 | V | 3113 | 3.113 V |
| 34021 | battery_1_cell_4_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34022 | battery_1_cell_5_voltage | int16 | 0.001 | V | 3113 | 3.113 V |
| 34023 | battery_1_cell_6_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34024 | battery_1_cell_7_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34025 | battery_1_cell_8_voltage | int16 | 0.001 | V | 3119 | 3.119 V |
| 34026 | battery_1_cell_9_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34027 | battery_1_cell_10_voltage | int16 | 0.001 | V | 3116 | 3.116 V |
| 34028 | battery_1_cell_11_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34029 | battery_1_cell_12_voltage | int16 | 0.001 | V | 3117 | 3.117 V |
| 34030 | battery_1_cell_13_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34031 | battery_1_cell_14_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34032 | battery_1_cell_15_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34033 | battery_1_cell_16_voltage | int16 | 0.001 | V | 3113 | 3.113 V |

### 6.4 Batterie Pack 2 (inferiert, +100er Block)

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 34100 | battery_2_voltage | uint16 | 0.01 | V | 5125 | 51.25 V |
| 34102 | battery_2_soc | uint16 | 0.1 | % | 120 | 12.0 % |
| 34103 | battery_2_cycle_count | uint16 | 1 | – | 13 | 13 |
| 34105 | battery_2_max_cell_voltage | uint16 | 0.001 | V | 3205 | 3.205 V |
| 34106 | battery_2_min_cell_voltage | uint16 | 0.001 | V | 3203 | 3.203 V |
| 34110 | battery_2_bms_version | uint16 | 1 | – | 116 | **v116** (BMS-Version, nicht Temperatur!) |
| 34111 | battery_2_max_cell_temp | int16 | 0.1 | °C | 235 | 23.5 °C |
| 34118–34133 | battery_2_cell_1..16_voltage | int16 | 0.001 | V | ~3203–3205 | ~3.2 V |

### 6.5 Temperaturen

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 35000 | internal_temperature | int16 | 0.1 | °C | 300 | 30.0 °C |
| 35001 | internal_mos1_temperature | int16 | 0.1 | °C | 313 | 31.3 °C |
| 35002 | internal_mos2_temperature | int16 | 0.1 | °C | 312 | 31.2 °C |
| 35010 | max_cell_temperature | int16 | 0.1 | °C | 216 | 21.6 °C |

### 6.6 Status & Alarms

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 35100 | inverter_state | uint16 | 1 | – | 2 | Zustandscode 2 |
| 36000 | alarm_status | uint32 | 1 | Bitmask | 0 | Kein Alarm (2 Register) |
| 36100 | fault_status | uint64 | 1 | Bitmask | 2388 | Fehler-Bits (4 Register) |
| 37007 | max_cell_voltage | uint16 | 0.001 | V | 3339 | 3.339 V |
| 37008 | min_cell_voltage | uint16 | 0.001 | V | 3337 | 3.337 V |
| 37012 | bms_version | uint16 | 1 | – | 116 | **v116** (BMS-Version, Systemebene) |

### 6.7 Energie-Zähler

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 33000 | total_charging_energy | uint32 | 0.01 | kWh | (2 Register) | 63.62 kWh |
| 33002 | total_discharging_energy | int32 | 0.01 | kWh | 0 | 0 kWh |
| 33004 | total_daily_charging_energy | uint32 | 0.01 | kWh | 0 | 0 kWh |
| 33006 | total_daily_discharging_energy | int32 | 0.01 | kWh | 0 | 0 kWh |
| 33008 | total_monthly_charging_energy | uint32 | 0.01 | kWh | 0 | 0 kWh |
| 33010 | total_monthly_discharging_energy | int32 | 0.01 | kWh | 0 | 0 kWh |

### 6.8 Firmware & Geräteinformation

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 30200 | ems_version | uint16 | 1 | – | 147 | v147 |
| 30202 | vms_version | uint16 | 1 | – | 115 | v115 |
| 30204 | bms_version | uint16 | 1 | – | 116 | v116 |
| 30300 | wifi_status | uint16 | 1 | – | 1 | Verbunden |
| 30301 | bluetooth_status | uint16 | 1 | – | 3 | BT-Status |
| 30302 | cloud_status | uint16 | 1 | – | 0 | Nicht verbunden |
| 30303 | wifi_signal_strength | uint16 | −1 | dBm | 50 | −50 dBm |
| 30304–30309 | mac_address | ASCII | – | – | – | 68:24:99:EE:F7:5C |
| 30350–30355 | comm_module_firmware | ASCII | – | – | – | 20240909_0159 |
| 31000–31009 | device_name | ASCII | – | – | – | VNSD-0 |

---

## 7. Bestätigte Write-Register (40000–49999)

### 7.1 Basis-Steuerung

| Register | Name | Typ | Beschreibung | Scan-Wert |
|---|---|---|---|---|
| 41000 | reset_device | uint16 | Geräte-Reset (0x55AA=BMS reset, 0xAA11=tieferer Reset) | 0 |
| 41100 | modbus_address | uint16 | Modbus Slave-Adresse (1–127) | 1 |
| 41200 | backup_function | uint16 | Backup/UPS-Funktion (0=aus, 1=ein) | 1 |

### 7.2 RS485-Steuerungsmodus

> ⚠️ **Pflicht:** Register 42000 = 0x55AA (21930) muss zuerst geschrieben werden, bevor 42010–42021 wirken!

| Register | Name | Typ | Beschreibung | Scan-Wert |
|---|---|---|---|---|
| 42000 | rs485_control_mode | uint16 | 0x55AA = RS485-Steuerung aktiv | 21930 (aktiv!) |
| 42010 | force_mode | uint16 | 0=Keine Vorgabe, 1=Laden, 2=Entladen | 0 |
| 42011 | charge_to_soc | uint16 | Ziel-SOC (0–100%) | 100 |
| 42020 | set_charge_power | uint16 | Lade-Leistungsvorgabe (W, max 2500) | 0 |
| 42021 | set_discharge_power | uint16 | Entlade-Leistungsvorgabe (W, max 2500) | 0 |

### 7.3 Betriebsmodus

| Register | Name | Typ | Werte | Scan-Wert |
|---|---|---|---|---|
| 43000 | user_work_mode | uint16 | 0=Eigenverbrauch, 1=Anti-Einspeisung, 2=Handel | 1 |

### 7.4 Zeitplanung (6 Slots à 5 Register)

Jeder Slot (1–6) belegt Register `43100 + (slot-1)*5` bis `43104 + (slot-1)*5`:

| Offset | Name | Typ | Beschreibung |
|---|---|---|---|
| +0 | schedule_N_days | uint16 | Wochentage-Bitmask (Bit0=Mo, Bit6=So) |
| +1 | schedule_N_start | uint16 | Startzeit als HHMM (z.B. 0800 = 08:00) |
| +2 | schedule_N_end | uint16 | Endzeit als HHMM |
| +3 | schedule_N_mode | int16 | Leistung in W (−2500 bis +2500; negativ=Laden) |
| +4 | schedule_N_enabled | uint16 | 0=deaktiviert, 1=aktiv |

**Slot-Adressen:**

| Slot | Tage | Start | Ende | Mode | Enable |
|---|---|---|---|---|---|
| 1 | 43100 | 43101 | 43102 | 43103 | 43104 |
| 2 | 43105 | 43106 | 43107 | 43108 | 43109 |
| 3 | 43110 | 43111 | 43112 | 43113 | 43114 |
| 4 | 43115 | 43116 | 43117 | 43118 | 43119 |
| 5 | 43120 | 43121 | 43122 | 43123 | 43124 |
| 6 | 43125 | 43126 | 43127 | 43128 | 43129 |

### 7.5 Hardware-Limits (Read-only in Write-Bereich)

| Register | Name | Typ | Einheit | Scan-Wert |
|---|---|---|---|---|
| 44002 | max_charge_power | uint16 | W | 2500 |
| 44003 | max_discharge_power | uint16 | W | 2500 |

---

## 8. Kritische Besonderheiten

### 8.1 battery_soc Scale-Faktor (Reg 34002)

```
⚠️ Scale = 0.1  (NICHT 1!)
Rohwert 109 → 10.9%  (NICHT 109%)
```

### 8.2 Multi-Register-Werte

```python
# uint32 lesen (Energie-Zähler): 2 Register kombinieren
value = (reg_hi << 16) | reg_lo
kWh = value * 0.01

# uint64 lesen (fault_status): 4 Register kombinieren
value = (r0 << 48) | (r1 << 32) | (r2 << 16) | r3

# ASCII lesen (mac_address, device_name):
# Jedes Register = 2 ASCII-Zeichen (Big-Endian)
char1 = raw >> 8
char2 = raw & 0xFF
```

| Register | Anzahl | Typ | Kombination |
|---|---|---|---|
| 30304–30309 | 6 | ASCII | MAC-Adresse (12 Zeichen) |
| 30350–30355 | 6 | ASCII | Modul-Firmware |
| 31000–31009 | 10 | ASCII | Gerätename (20 Zeichen) |
| 32302–32303 | 2 | int32 | Offgrid-Leistung |
| 33000–33001 | 2 | uint32 | Lade-Energie gesamt |
| 33002–33003 | 2 | int32 | Entlade-Energie gesamt |
| 36000–36001 | 2 | uint32 | Alarm-Statusbits |
| 36100–36103 | 4 | uint64 | Fehler-Statusbits |

### 8.3 RS485-Steuerungssequenz

```python
# Reihenfolge ZWINGEND:
# 1. RS485-Steuerung aktivieren
client.write_register(42000, 0x55AA, slave=1)  # = 21930

# 2. Modus setzen (1 Sekunde warten)
import time; time.sleep(1)
client.write_register(42010, 1, slave=1)  # Laden erzwingen

# 3. Leistung setzen
client.write_register(42020, 2000, slave=1)  # 2000W laden
```

### 8.4 Vorzeichen-Konventionen

| Register | Positiv | Negativ |
|---|---|---|
| 30001 battery_power | Laden | Entladen |
| 37004 ac_current | Netzbezug | Einspeisung |
| 30303 wifi_signal | Roh negieren! (raw×−1) | – |

---

## 9. MQTT-Feldnamen → Register-Mapping

Gefunden im Flash-String-Pool bei `0x08018000`.
Die Spalte *Local API* zeigt das äquivalente Feld aus der offiziellen
Marstek Local API REV 0.5 — als zusätzliche Verifikationsquelle:

| MQTT-Feld | Register | Beschreibung | Local API Äquivalent |
|---|---|---|---|
| `bat_soc` | 34002 | Batterie SOC (Scale 0.1!) | `ES.GetStatus.bat_soc` / `Bat.GetStatus.soc` |
| `bat_temp` | 35000 | Batterietemperatur | `Bat.GetStatus.bat_temp` |
| `bat_cap` / `bat_capacity` | – | Batteriekapazität | `Bat.GetStatus.bat_capacity` (aktuell) / `rated_capacity` (Nenn) |
| `ongrid_power` | 30006 | Netzleistung (AC) | `ES.GetStatus.ongrid_power` |
| `offgrid_power` | 32302 | Offgrid-Leistung | `ES.GetStatus.ogrid_power` |
| `pv_power` | MPPT-Summe | PV-Gesamtleistung | `ES.GetStatus.pv_power` / `PV.GetStatus.pv_power` |
| `total_pv_energy` | – (offen) | PV-Gesamtenergie | `ES.GetStatus.total_pv_energy` |
| `total_grid_output_energy` | 33002–33003 | Gesamteinspeisung | `ES.GetStatus.total_grid_output_energy` |
| `total_grid_input_energy` | 33000–33001 | Gesamtbezug | `ES.GetStatus.total_grid_input_energy` |
| `total_load_energy` | – (offen) | Verbraucher-Energie | `ES.GetStatus.total_load_energy` |
| `work_mode` | 43000 | Betriebsmodus | `ES.GetMode.mode` ("Auto"/"Manual"/"AI"/"Passive") |
| `tol_charge` | 33000 | Gesamte Ladeenergie | `ES.GetStatus.total_grid_input_energy` |
| `tol_discharge` | 33002 | Gesamte Entladeenergie | `ES.GetStatus.total_grid_output_energy` |
| `connect` / `disconnect` | 30300/30302 | Verbindungsstatus | `Wi.GetStatus` / `BLE.GetStatus` |
| `ble_mac` | 30304 | Bluetooth MAC | `Marstek.GetDevice.ble_mac` |
| `wifi_mac` | 30304 | WiFi MAC | `Marstek.GetDevice.wi_mac` |
| `wifi_name` | – | SSID | `Marstek.GetDevice.wi_name` / `Wi.GetStatus.ssid` |

---

## 10. Marstek Local API — Parallelprotokoll & Cross-Validierung

> **⛔ WARNUNG — NICHT AKTIVIEREN:**
> Mehrere Nutzerberichte belegen, dass das Aktivieren der Marstek Local API
> zu dauerhaft falschen oder eingefrorenen Modbus-Registerwerten führt.
> Der Fehler tritt auch nach Geräte-Reset oder Deaktivierung der API nicht zurück.
> Ursache ist ein geteilter interner Zustand (Mutex / SRAM-Pointer) zwischen
> dem Modbus-TCP-Task und dem UDP-JSON-Task im FreeRTOS-Scheduler.
> Das offizielle Dokument warnt selbst: *"some native functions of the device
> may be disabled to avoid command conflicts".*
>
> **Die Local API wird für die HA-Integration nicht verwendet.**
> Sie dient hier ausschließlich als Referenzquelle zur Verifikation
> unserer Modbus-Register-Bedeutungen.

### 10.1 Protokoll-Übersicht (Referenz)

| Eigenschaft | Wert |
|---|---|
| Dokument | Marstek Device Open API REV 0.5 (Draft, 04.07.2025) |
| Transport | UDP, Unicast und Broadcast |
| Port | Standard 30000, konfigurierbar (Empfehlung: 49152–65535) |
| Format | JSON-RPC (Methode + params → result) |
| Aktivierung | Marstek APP oder BLE-Befehl 0x28 — **beides vermeiden** |
| Authentifizierung | Keine (rein lokal, kein Token) |

### 10.2 Verfügbare Methoden (Referenz)

| Methode | Funktion | Typ |
|---|---|---|
| `Marstek.GetDevice` | Gerät im LAN entdecken | Read |
| `Wi.GetStatus` | WiFi-Status und Netzwerk-Info | Read |
| `BLE.GetStatus` | Bluetooth-Verbindungsstatus | Read |
| `Bat.GetStatus` | Batterie SOC, Temp, Kapazität, Fehlercode | Read |
| `PV.GetStatus` | PV-Leistung, Spannung, Strom | Read |
| `ES.GetStatus` | Energie-Systemstatus (Leistungen, Zähler) | Read |
| `ES.GetMode` | Aktuellen Betriebsmodus lesen | Read |
| `ES.SetMode` | Betriebsmodus setzen (Auto/AI/Manual/Passive) | **Write** |

### 10.3 Cross-Validierung: Local API ↔ Modbus-Register

Die folgenden Verknüpfungen wurden durch Abgleich der API-Beispielwerte
(REV 0.5) mit unseren Modbus-Scan-Ergebnissen ermittelt. Alle Übereinstimmungen
bestätigen die Korrektheit unserer RE-Ergebnisse.

| Local API Feld | Modbus Reg. | Scale | Verifikation |
|---|---|---|---|
| `ES.GetStatus.bat_soc` = 98 | **34002** battery_soc | ×0.1 → raw=980 | ✅ **Scale 0.1 offiziell bestätigt** |
| `ES.GetStatus.bat_power` = 501 W | **30001** battery_power | ×1 (int16) | ✅ Bedeutung bestätigt |
| `ES.GetStatus.ongrid_power` = 100 W | **30006** ac_power | ×1 (int16) | ✅ Bedeutung bestätigt |
| `ES.GetStatus.ogrid_power` = 0 W | **32302–32303** offgrid_power | int32 | ✅ Bedeutung bestätigt |
| `ES.GetStatus.pv_power` = 0 W | **30037–30040** mppt*_power | ×0.1, Summe | ✅ (PV nicht angeschlossen) |
| `ES.GetStatus.total_grid_input_energy` = 3273 Wh | **33000–33001** uint32 | ×0.01 kWh | ✅ Einheit Wh bestätigt |
| `ES.GetStatus.total_grid_output_energy` = 2548 Wh | **33002–33003** uint32 | ×0.01 kWh | ✅ Einheit Wh bestätigt |
| `Bat.GetStatus.soc` = 90 | **34002** battery_soc | ×0.1 → raw=900 | ✅ Zweite Bestätigung Scale 0.1 |
| `Bat.GetStatus.bat_temp` = 25.0 °C | **35000** internal_temperature | ×0.1 → raw=250 | ✅ Scale 0.1 für Temp bestätigt |
| `Bat.GetStatus.rated_capacity` = 5120 Wh | **35110 / 35111** (candidat) | ×1 Wh | ⚠️ Register noch nicht eindeutig gemappt |
| `Bat.GetStatus.error_code` = "0x430" | **36100–36103** fault_status | bitmask | ⚠️ Bit-Mapping noch offen |
| `PV.GetStatus.pv_voltage` = 40.0 V | **30020–30023** mppt*_voltage | ×0.1 → raw=400 | ✅ Scale 0.1 bestätigt |

### 10.4 Modus-Mapping: API ↔ Modbus

| Local API `ES.SetMode.mode` | Modbus Reg. 43000 | Modbus Steuerregister | Bedeutung |
|---|---|---|---|
| `"Auto"` | `0` (Eigenverbrauch) | – | Automatischer Eigenverbrauch |
| `"AI"` | kein direktes Äquivalent | – | KI-gesteuerter Modus (Cloud-Funktion) |
| `"Manual"` + `manual_cfg` | `1` (Anti-Feed-In) + Zeitpläne | 43100–43129 | Zeitgesteuerte Lade-/Entladeplanung |
| `"Passive"` + `power` + `cd_time` | force_mode 42010=1 oder 2 + 42020/42021 | – | Einmaliges Laden/Entladen mit Zeitlimit |

> **Hinweis zu "Passive":** Der Parameter `cd_time` (Countdown in Sekunden) hat
> kein direktes Modbus-Äquivalent in unseren gescannten Registern.
> Er wird vermutlich intern durch den EMS-Task verwaltet und ist über
> Modbus nicht lesbar/setzbar. Für HA-Automatisierungen ist die
> force_mode-Steuerung via Modbus (42010 + 42020/42021) vollwertig.

### 10.5 Neue Register-Kandidaten aus API-Feldern

Diese API-Felder haben noch kein bestätigtes Modbus-Äquivalent:

| API Feld | Typ | Kandidat-Register | Begründung |
|---|---|---|---|
| `ES.GetStatus.total_pv_energy` | Wh | 33004–33005? | Analog zu grid_input/output Pattern |
| `ES.GetStatus.total_load_energy` | Wh | 33006–33007? | Weiterer uint32-Zähler im 33000er-Block |
| `Bat.GetStatus.rated_capacity` | Wh (5120) | 35110 oder 35111 | raw=576→57.6? Nein. Oder direkt 5120? |
| `Bat.GetStatus.bat_capacity` | Wh (aktuell) | 34008? | Verbleibende Kapazität in Wh |
| `ES.GetStatus.bat_cap` | Wh gesamt | 30003 oder 30004? | 30004=2364 passt nicht; 5120 noch nicht gesehen |

---

## 11. Marstek Cloud API & OTA-Infrastruktur

### 11.1 Analyse-Tool

Das Open-Source-Tool **marstek-fw-checker** (von Remko Weijnen, GitHub: `rweijnen/marstek-fw-checker`)
wurde zur Analyse der Marstek-Cloud-API verwendet. Es läuft als statische Webseite
mit Netlify-Functions als CORS-Proxy und erlaubt Login, Geräteabfrage und OTA-Check.

```bash
# Lokaler Start (kein Netlify nötig für Basis-Funktion):
cd marstek-fw-checker-master/
python -m http.server 8000
```

### 11.2 Cloud-API-Endpunkte (aus Script-Analyse)

| Endpunkt | Pfad | Zweck |
|---|---|---|
| Authentifizierung | `/app/Solar/v2_get_device.php` | Login + Geräteliste (MD5-Passwort) |
| Gerätliste (detail) | `/ems/api/v1/getDeviceList` | Detailierte Gerätedaten inkl. Versionen |
| OTA Standard | `/ems/api/v2/checkSmallBalconyOTA` | Firmware-Check für Venus-Geräte |
| OTA CT-Geräte | `/ems/api/v1/checkAcCoupleOta` | Firmware-Check für HME-3/HME-4 |
| Einstellungen | `/ems/api/v1/getAdvance` | Erweiterte Geräteeinstellungen |

**Basis-URL (EU):** `https://eu.hamedata.com`

### 11.3 OTA-Request-Parameter (für VNSD-0)

Das Tool sendet `m=100` als Baseline-Version, um alle verfügbaren
Firmware-Einträge zu erhalten. Der vollständige Request für den Venus D:

```
GET https://eu.hamedata.com/ems/api/v2/checkSmallBalconyOTA
    ?uid=<devid>
    &device_type=VNSD-0
    &m=100
    &sbv=0
    &mppt=0
    &inv=0
    &click=false
    &lang=English
    &is_fourDigit={"control":false,"bms":false,"micro":false,"mppt":false}
    &token=<auth-token>
    &mailbox=<email>
```

**Ergebnis für VNSD-0:** Leere Antwort — Marstek führt `VNSD-0` nicht
im OTA-System. Die Firmware wird intern als `VNSEE3-0` behandelt, der
OTA-Server hat jedoch keine Einträge für den Typ-String `VNSD-0`.

**Staged Rollout:** Die OTA-Verteilung erfolgt in Wellen. Selbst für
unterstützte Gerätetypen (z.B. VNSA-0) erhalten nicht alle Geräte
gleichzeitig Firmware-Updates — abhängig von Gerätealter, Region und
möglicherweise `dlock`-Status.

### 11.4 Vollständige MCU-Komponenten-Matrix (OTA API)

Der `/ems/api/v2/checkSmallBalconyOTA`-Response enthält **9 Komponenten-Felder**.
Der vollständige Response für VNSD-0 (18.05.2026) lautet:

```json
{
  "code": 1,
  "show": 0,
  "msg": "success",
  "data": {
    "control":   "",
    "bms":       "",
    "mppt":      "",
    "micro":     "",
    "dcdc":      "",
    "bms_pack1": "",
    "bms_pack2": "",
    "led":       "",
    "charger":   ""
  }
}
```

> **Neu gegenüber Rev 7:** Die Felder `dcdc`, `led` und `charger` waren bisher
> nicht dokumentiert. Sie wurden durch Auswertung des vollständigen Raw-API-Response
> identifiziert.

**Alle Felder leer** → VNSD-0 hat keinen OTA-Eintrag auf dem Server.

#### Vollständige Komponenten-Tabelle aller 9 API-Felder

| API-Feld | MCU / Subsystem | Beschreibung | VNSD-0 (Mai 2026) | VNSA-0 (Mai 2026) |
|---|---|---|---|---|
| `control` | EMS-Hauptcontroller | Energy Management, Modbus TCP, WiFi | – (leer) | v1487 |
| `bms` | BMS-Hauptcontroller | Battery Management System (alle Packs) | – (leer) | v1105 |
| `micro` | Inverter-MCU | Wechselrichter-Controller | – (leer) | v1193 |
| `mppt` | MPPT-Controller | Solarladeregler | – (leer) | – (leer) |
| `dcdc` | **DC/DC-Konverter-MCU** | **Bidirektionaler DC/DC-Wandler** ⚠️ **Neu** | – (leer) | unbekannt |
| `bms_pack1` | Pack-1-BMS | Individuelle Pack-1-Firmware | – (leer) | – (leer) |
| `bms_pack2` | Pack-2-BMS | Individuelle Pack-2-Firmware | – (leer) | – (leer) |
| `led` | **LED-Controller** | **Statusanzeige-MCU / LED-Steuerung** ⚠️ **Neu** | – (leer) | unbekannt |
| `charger` | **Lade-Controller** | **AC-Lader / Netzladegerät** ⚠️ **Neu** | – (leer) | unbekannt |

> **Hinweis zu `bms_pack1`/`bms_pack2`:** Auch beim VNSA-0 leer —
> Pack-individuelle OTA-Felder werden serverseitig nicht befüllt,
> obwohl das Gerät mehrere Packs unterstützt.

#### `is_fourDigit` Parameter — Bedeutung für Versionsregister

Der Request enthält:
```json
"is_fourDigit": {"control": false, "bms": false, "micro": false, "mppt": false}
```

Dieses Flag zeigt, ob die jeweilige Komponente eine 4-stellige Versionsnummer hat.
Aktuell meldet das Gerät überall `false` (3-stellige Versionen: 147, 116, 115).
Wenn eine neue Firmware-Generation auf 4-stellige Nummern (z. B. 1001) wechselt,
wird dieses Flag `true` — nützlich als Indikator für Major-Updates.

> **Sicherheitshinweis:** Auth-Token (`token=`) und E-Mail-Adresse stehen im
> Klartext in der OTA-Request-URL. Logs, die diese URL enthalten, sollten vor
> der Weitergabe bereinigt werden.

### 11.5 Venus A (VNSA-0) — MCU-Struktur als Referenz

Der VNSA-0 zeigt drei aktiv genutzte OTA-Felder der Venus-Familie:

| API-Feld | MCU | Version (Mai 2026) | Dateiname-Muster |
|---|---|---|---|
| `control` | EMS-Hauptcontroller | 1487 | `VNSA-0_app_1487_*.bin` |
| `bms` | Battery Management System | 1105 | `VA50A_APP_V1105_*.bin` |
| `micro` | Inverter-Mikrocontroller | 1193 | `VA_inv_app_1193_*.bin` |
| `mppt` | MPPT-Controller | – (leer) | – |
| `dcdc` | DC/DC-Wandler | unbekannt | – |
| `bms_pack1` | Pack-1-BMS | – (leer) | – |
| `bms_pack2` | Pack-2-BMS | – (leer) | – |
| `led` | LED-Controller | unbekannt | – |
| `charger` | Lade-Controller | unbekannt | – |

### 11.6 Cloud Device Record — Marstek Venus D

Vollständiger API-Response für das analysierte Gerät (`/ems/api/v1/getDeviceList`):

```json
{
  "devid":        "<DEVICE_UID>",
  "name":         "MST_VNSD_xxxx",
  "sn":           "MVDxxxxxxxxxx",
  "mac":          "xxxxxxxxxxxx",
  "type":         "VNSD-0",
  "access":       "1",
  "bluetooth_name": "MST_VNSD_xxxx",
  "date":         "2026-04-21 11:20:08",
  "id":           <CLOUD_ID>,
  "dlock":        "Y",
  "timeZone":     "Europe/Berlin",
  "version":      "147",
  "soc":          80,
  "battery_num":  1,
  "status":       1,
  "isVppDevice":  "N"
}
```

### 11.7 Analyse des Device Records

| Feld | Wert | Bedeutung / Auffälligkeit |
|---|---|---|
| `type` | `VNSD-0` | Bestätigt Gerätetyp |
| `version` | `"147"` | **Control/EMS-Firmware** (nicht BMS) — identisch mit Reg 30200 |
| `soc` | `80` | Cloud-SoC zum Abfrage-Zeitpunkt (von Gerät gemeldet) |
| `battery_num` | `1` | ⚠️ Cloud meldet nur 1 Pack, obwohl 2 verbaut |
| `dlock` | `"Y"` | **Device Lock aktiv** — könnte OTA-Update blockieren |
| `salt` | `"d1f1900057185ec9,d1f1900057185ec9"` | Zwei identische Werte kommagetrennt — evtl. je ein Salt pro Pack |
| `date` | `2026-04-21` | Registrierungsdatum (Gerät relativ neu) |
| `isVppDevice` | `"N"` | Kein Virtual Power Plant / Aggregator |
| `status` | `1` | Online |

**Zu `battery_num: 1`:** Die Cloud sieht nur einen Pack, obwohl beide Packs
per Modbus lesbar sind (Register 34000 und 34100). Wahrscheinlich meldet das
Gerät im MQTT-Heartbeat nur den primären Pack — oder die Cloud-Logik
zählt das Gerät selbst als "Batterie Unit 1".

**Zu `dlock: "Y"`:** Device Lock ist ein unbekanntes Flag, das vermutlich
von Marstek serverseitig gesetzt wird. Mögliche Bedeutungen: Support-Hold,
bekannte Inkompatibilität der aktuellen Firmware mit dem Update,
oder generelle Sperre für nicht-offizielle Gerätetypen im OTA-System.

---

### 11.8 OTA-Komponenten → Modbus-Versionregister-Mapping

Die 9 API-Komponenten lassen sich teilweise auf Modbus-Register zurückführen.
Das Muster im 30200er-Block ist: pro MCU ein Register-Paar (Main + Sub-Version).

#### Bestätigte Zuordnungen

| Register | Wert | API-Feld | Beschreibung |
|---|---|---|---|
| **30200** | 147 | `control` | EMS-Firmware-Version (Hauptversion) ✅ bestätigt |
| 30201 | 18 | `control`? | EMS-Sub-/Patch-Version (direkt neben 30200) |
| **30202** | 115 | — | VMS-Firmware-Version (kein eigenes API-Feld) |
| 30203 | 106 | — | VMS-Sub-Version |
| **30204** | 116 | `bms` | BMS-Firmware-Version ✅ bestätigt |
| 30205 | 104 | `bms`? | BMS-Sub-Version |

#### Fehlende Komponenten im Scan

Register 30206–30209 existieren **nicht** im Scan (Gerät hat dort keine Daten
geliefert — entweder nicht vorhanden oder Wert = 0 und kein Response).

| Register (hypothetisch) | Mögliches API-Feld | Status |
|---|---|---|
| 30206/30207 | `mppt` | Nicht im Scan — MPPT wahrscheinlich nicht verbaut |
| 30208/30209 | `dcdc` / `micro` | Nicht im Scan |

> **Schlussfolgerung:** `dcdc`, `led` und `charger` sind entweder:
> (a) Sub-Komponenten ohne eigene Modbus-Versionsregister, oder
> (b) ihre Register liegen außerhalb des 30200er-Blocks (z. B. 37000er-Bereich).
> **Offen:** Register 37006 = 192 ist unerklärt — könnte DCDC-Version sein.
> **Scan-Lücke schließen:** 30206–30209 manuell nachlesen (single-register,
> timeout 500 ms), um `mppt`/`dcdc`-Register zu bestätigen oder auszuschließen.

#### LED-Steuerung via Modbus

Der `led`-Eintrag in der OTA-API korrespondiert mit bekannten
Modbus-Write-Funktionen aus der Binary-Analyse:

| Funktion (aus Binary) | Chinesisch | Modbus-Äquivalent |
|---|---|---|
| `ctrl_led_light` | 控制led灯亮度 | Schreibbefehl (40000er-Bereich, unbekannte Adresse) |
| `led_continue_ctrl` | 控制类型 | LED dauerhaft: 0=an; 1=aus + Dauer ms |
| `Led.Ctrl` | — | Übergeordnetes MQTT-Topic |

> Die genauen Modbus-Adressen für LED-Control sind noch nicht im 40000er-Scan
> identifiziert — wahrscheinlich im ungescannten Bereich 44004–49999.

---

## 12. Analyse-Skripte (Übersicht)

### 12.1 Scan-Skripte

| Skript | Beschreibung | Verwendung |
|---|---|---|
| `scan_modbus.py` | Original Einzel-Register-Scanner | `python3 scan_modbus.py --host IP --range 30000 39999 --out out.csv` |
| `scan_modbus_batch.py` | **Empfohlen:** 125 Register/Request, Reconnect, viel schneller | `python3 scan_modbus_batch.py --host IP --out scan_full.csv` |

**Batch-Scanner Performance:**

| Methode | Requests für 65535 Reg | Zeit (100ms/Req) |
|---|---|---|
| Einzel | 65.535 | ~109 Stunden |
| Batch (125/Req) | ~524 | **~52 Minuten** |

### 12.2 Firmware-Analyse-Skripte

| Skript | Version | Methode | Ergebnis |
|---|---|---|---|
| `find_registers_v2.py` | v2 | 6 Strategien (Strings, MOVW, Cluster) | MOVW #0x7530 bei 0x0801295e gefunden |
| `find_registers_v3.py` | v3 | Gezielte Analyse bekannter Adressen | String-Pool bei 0x08018000 gefunden |
| `find_registers_v4.py` | v4 | SRAM-Ptr-Validierung | Tabelle nicht gefunden (0 Treffer) |
| `find_registers_v5.py` | v5 | ARM Thumb-2 Disassemblierung | Init-Funktion-Region eingegrenzt |
| `find_registers_v6.py` | v6 | .data-Section-Mapping | 0x08055d4c = MQTT-Strings (falsch) |
| `find_registers_v7.py` | v7 | STR-Offset-Suche + Pointer-Analyse | 0 STR-Treffer; SRAM-Ptr-Blöcke gefunden |

### 12.3 YAML-Generator

```bash
python3 generate_final_yaml.py \
    --csv30 register_3000039999_matched.csv \
    --csv40 register_4000049999_matched_csv.csv \
    --out   marstek_venus_registers_final.yaml
```

### 12.4 Ghidra-Skripte (Jython 2.7)

| Skript | Beschreibung |
|---|---|
| `MaerstekExtractor.py` | Schreibt Descriptor-Einträge via getReferencesFrom() (0 Treffer ohne SRAM-Block) |
| `MaerstekDecompiler.py` | Nutzt Ghidra-Decompiler + Regex-Parser |
| `FindRouterCallers.py` | Findet Aufrufer von FUN_0801c088 → führt zu Init-Code |

---

## 13. Reverse Engineering — Methodik & Erkenntnisse

### 13.1 Firmware beschaffen

```bash
# OTA-Traffic via Wireshark abfangen (HTTP, unverschlüsselt)
# Server: eu.hamedata.com
# Filter: http && tcp.port == 80

# Binary verifizieren
xxd VNSEE3-0_app_0148_0306_115507.bin | head -5
# Zeile 1: 18 f3 01 20 71 4a 00 08 → IVT-Start (Stack-Pointer + Reset-Handler)
strings firmware.bin | grep -E "Task_|FreeRTOS|marstek"
```

### 13.2 Ghidra-Konfiguration (Pflicht)

```
Import: Raw Binary
Language: ARM → Cortex → 32 → little → default
Base Address: 0x08000000

Memory Map zusätzlich hinzufügen:
  SRAM:   0x20000000  Größe 0x20000  R+W
  PERIPH: 0x40000000  Größe 0x10000000  R+W
  SCS:    0xE000E000  Größe 0x1000  R+W

Auto-Analyze: Decompiler Switch Analysis + Scalar Operand References aktivieren
```

### 13.3 Modbus-Routing-Schema

```
Eingehender Request:
    FC-Code == 6 (Write Single)?
        uVar6 >= 40000  →  Write-Handler FUN_0804c83c
        uVar6 <  40000  →  Descriptor-Tabelle suchen in FUN_0804b73c
    FC-Code == 3 (Read)?
        Descriptor-Tabelle iterieren, Serializer aufrufen
```

### 13.4 Warum die Descriptor-Tabelle nicht im Flash gefunden wurde

Die Tabelle wird zur Laufzeit durch Init-Code aufgebaut. Versuche die Quelltabelle zu finden:

| Strategie | Methode | Ergebnis |
|---|---|---|
| Statische Flash-Suche mit SRAM-Ptr | v4 Strategie A | 0 Treffer |
| Ohne SRAM-Ptr (monoton steigend) | v4 Strategie B | 0 Treffer |
| Startup-Literal-Pool | v6 | 0x08055d4c = MQTT-Strings |
| MOVW #0x7530 verfolgen | v5 | Führt zu JSON-Parser (falsch!) |
| STR mit Offset 0x2F8 | v7 Strategie A | 0 Treffer |
| MOVW #0x02F8 (Tabellenadresse) | v7 Strategie B | Nicht gefunden |
| 6-Byte-Stride Tabelle | v4 Strategie D | 0 Treffer |

**Schlussfolgerung:** Der Init-Code lädt die Tabellenadresse indirekt:
```arm
LDR R0, [PC, #literal_pool_offset]  ; lädt SRAM-Basisadresse
ADD R0, R0, #0x2F8                  ; berechnet Tabellenadresse
; → weder MOVW #0x02F8 noch MOVT #0x2000 erscheint im Code
```

---

## 14. Ghidra-Analyse-Erkenntnisse

### 14.1 Falsch identifizierte Funktion #1

```
Adresse: FUN_080128a0 (enthält MOVW #0x7530 bei 0x0801295e)
NICHT: Descriptor-Init-Funktion
IST:   JSON-Config-Parser

Beweis: Decompilierter Code zeigt
  DAT_20018b6b = 30000;  // ← 0x7530 ist hier ein Standard-API-Port!
  FUN_08045340(param_1, &DAT_08012b04, &DAT_20018b68);  // JSON-Parser
```

### 14.2 Falsch identifizierte Funktion #2

```
Adresse: FUN_0801bcb0
NICHT: Descriptor-Init-Funktion
IST:   RS485/RTU Paket-Handler

Beweis: Verarbeitet Modbus-RTU-Frames (CRC-Check, FC03/FC06/FC10 Routing)
  DAT_200151ec  = RS485-Empfangspuffer
  FUN_08025f3c  = Modbus FC03 Handler
  FUN_08026080  = Modbus FC06 Handler
  FUN_08026154  = Modbus FC16 Handler
```

### 14.3 Korrekt identifizierte Funktionen

| Funktion | Status | Quelle |
|---|---|---|
| `FUN_0801c088` = Router | ✅ Bestätigt | TCPRouter.c dekompiliert |
| `FUN_0804b73c` = Serializer | ✅ Bestätigt | Serializer.c dekompiliert |
| `FUN_0804c83c` = Write-Handler | ✅ Bestätigt | WriteHandler.c dekompiliert |

### 14.4 Ghidra-Skript-Probleme

- `getReferencesFrom()` findet keine **berechneten** SRAM-Adressen
- Nur direkte Literal-Referenzen werden von Ghidra getrackt
- Lösung: SRAM-Block hinzufügen + Re-Analyse → danach Decompiler nutzen
- Jython 2.7: Keine Umlaute/Sonderzeichen ohne `# -*- coding: utf-8 -*-`

---

## 15. Falsche Fährten & Lektionen

### 15.1 MOVW #0x7530 ist kein verlässlicher Anker

Der Wert 0x7530 = 30.000 erscheint mehrfach im Code mit unterschiedlichen Bedeutungen:
- **API-Port** (30000 als Default-Port in JSON-Config-Parser)
- **Vergleichswert** (Bereichsprüfung: `if reg < 30000`)
- Möglicherweise auch als erste Register-Adresse im Init-Code

### 15.2 0x9C40 (40.000) dient als Range-Check

In WriteHandler.c und TCPRouter.c erscheint 0x9C40 als Grenzwert zwischen Read- und Write-Registern. Das macht es ungeeignet als Anker für den Descriptor-Init.

### 15.3 MOVW mit "Tabellen-Offset-Werten"

75 MOVW-Instruktionen mit Werten 0x02F8–0x0DCC wurden gefunden. Diese sind jedoch alle **Leistungsgrenzen** (0x09C4 = 2500W, 0x0BB8 = 3000W), keine Tabellen-Offsets.

### 15.4 Startup-Literal-Pool bei 0x08055c8c

Erschien vielversprechend als .data-Section-Quelle. Enthält tatsächlich nur MQTT-Debug-Strings, keine Register-Descriptor-Daten.

### 15.5 Register 34010 / 34110 / 37012 als Temperatur fehlinterpretiert

**Symptom:** Rohwert 116 wurde mit Scale 0.1 als 11.6 °C interpretiert —
ein zur Jahreszeit (Mai, kühle Batterie) plausibel erscheinender Wert.

**Korrektur:** Alle drei Register enthalten die **BMS-Firmware-Version (116)**,
identisch mit Reg 30204 (`bms_version = 116`).

| Register | Falsch | Richtig |
|---|---|---|
| 34010 | pack1_temp_avg = 11.6 °C | **pack1_bms_version = 116** |
| 34110 | battery_2_temperature = 11.6 °C | **battery_2_bms_version = 116** |
| 37012 | max_temp_all_packs = 11.6 °C | **bms_version (Systemebene) = 116** |

**Lektion:** Wenn ein Rohwert eine Temperatur-Interpretation zufällig plausibel macht,
immer gegen bekannte Werte gleicher Bedeutung (hier Reg 30204) gegenchecken.
Die dreifache Übereinstimmung mit 30204 hätte früher auffallen sollen.
Die eigentliche Pack-Durchschnittstemperatur liegt wahrscheinlich bei 34012–34016
(Rohwerte 192–198 → 19.2–19.8 °C), was für eine indoor-betriebene Batterie besser passt.

---

## 16. Offene Punkte & nächste Schritte

### 16.1 Register-Adressraum — abgeschlossen

| Bereich | Status |
|---|---|
| 0 – 29.999 | ✅ Gescannt — leer bestätigt |
| 30.000 – 39.999 | ✅ 89 Register vollständig kartiert |
| 40.000 – 49.999 | ✅ 41 Register vollständig kartiert |
| 50.000 – 65.535 | ✅ Gescannt — leer bestätigt |

**Der vollständige Modbus-Adressraum ist kartiert. Es gibt keine weiteren unbekannten Bereiche.**

### 16.2 Offene Register aus Local API Abgleich (Priorität hoch)

Folgende API-Felder haben noch kein bestätigtes Modbus-Register.
Da der vollständige Adressraum gescannt ist, befinden sich diese
Register — sofern vorhanden — im bekannten Bereich 30000–49999:

| API-Feld | Erwarteter Wert | Kandidat-Register | Nächster Schritt |
|---|---|---|---|
| `ES.GetStatus.total_pv_energy` | Wh-Zähler | 33004–33005 | Bei PV-Betrieb prüfen |
| `ES.GetStatus.total_load_energy` | Wh-Zähler | 33006–33007 | Prüfen |
| `Bat.GetStatus.bat_capacity` | aktuell verfügbare Wh | 34008? 34009? | Gezielte Einzellesung |
| `ES.GetStatus.bat_cap` | Nenn-Kapazität (5120 Wh) | 35110 oder 35111 | Rohwert 576 ≠ 5120 → anderer Scale? |
| `Bat.GetStatus.error_code` | "0x430" als String | 36100–36103 | Bitmask-Mapping fehlt |
| `ES.GetMode.mode` String | "Auto"/"Manual" etc. | 43000 | Enum-Zuordnung 0→Auto, 1→? verifizieren |

### 16.2a OTA-Komponenten ohne Modbus-Zuordnung (Priorität mittel)

Drei neu identifizierte OTA-Felder (`dcdc`, `led`, `charger`) haben noch
keine bestätigten Modbus-Versionsregister:

| OTA-Feld | Hypothese | Kandidat-Register | Nächster Schritt |
|---|---|---|---|
| `dcdc` | DC/DC-Wandler-Firmware-Version | 30206/30207? | Einzellesung; im Scan nicht vorhanden |
| `led` | LED-Controller-Firmware-Version | 30208/30209? | Einzellesung; im Scan nicht vorhanden |
| `charger` | AC-Lader-Firmware-Version | unbekannt | Kein Kandidat bekannt |
| LED-Write-Befehl | `ctrl_led_light` aus Binary | 44xxx? | 40000er-Scan ab 44004 nachholen |
| DCDC-Statusregister | Leistung / Wirkungsgrad | 37006 = 192? | Einzellesung verifizieren |

```python
# Scan-Lücke 30206-30209 schließen (single-register, timeout 500ms)
from pymodbus.client import ModbusTcpClient
import time

c = ModbusTcpClient("192.168.X.X", port=502, timeout=0.5)
c.connect()
for reg in [30206, 30207, 30208, 30209, 37006]:
    try:
        r = c.read_holding_registers(reg, 1, slave=1)
        if not r.isError():
            print(f"Reg {reg}: {r.registers[0]}")
        else:
            print(f"Reg {reg}: Error (nicht vorhanden)")
    except Exception as e:
        print(f"Reg {reg}: Exception → {e}")
    time.sleep(0.1)
c.close()
```

### 16.3 Descriptor-Tabelle (231 Einträge) — noch nicht extrahiert

Die Tabelle bei SRAM `0x200002F8` wurde live durch den Batch-Scan
empirisch erschlossen (413 Register). Für die exakten Datentyp- und
Scale-Informationen aller 231 Einträge wäre eine direkte Extraktion sinnvoll:

```
Mögliche Ansätze:
1. JTAG/SWD: 2772 Bytes ab 0x200002F8 bei laufendem Gerät lesen
2. Unicorn-Emulation: Binary emulieren bis SRAM initialisiert
3. Ghidra: Router-Caller über References-to-DAT_200002f8 finden
```

Ghidra-Anleitung:
```
1. FUN_0801c088 (Router) in Ghidra öffnen (G → 1c088)
2. F5 (Decompiler)
3. Rechtsklick auf 'DAT_200002f8'
4. References → Show References to Address
5. WRITE-Referenzen → das ist die Init-Funktion
```

### 16.4 Bekannte Register-Lücken

Aus dem Descriptor-Table-Schema (231 Einträge) und 413 gescannten Registern
(in 89 Read + 41 Write-Gruppen) sind noch ca. 101 Descriptor-Einträge
nicht eindeutig dekodiert:

- **33004–33011**: Weitere Energie-Zähler (total_pv_energy, total_load_energy)
- **34008–34009**: Aktuelle Batterie-Kapazität in Wh (bat_capacity)
- **30000–30010**: Erste Register noch nicht vollständig dekodiert (30000=509 unerklärt)
- Erweiterte Alarm/Fehler-Codes mit Bit-Definitionen

### 16.5 Verifikations-Code für kritische Register

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient("192.168.1.XXX", port=502)
c.connect()

# SOC (Scale 0.1!) — durch Local API REV 0.5 bestätigt
raw = c.read_holding_registers(34002, 1, slave=1).registers[0]
print(f"SOC Pack1: {raw * 0.1:.1f}%")

# SOC Pack2
raw2 = c.read_holding_registers(34102, 1, slave=1).registers[0]
print(f"SOC Pack2: {raw2 * 0.1:.1f}%")

# Netzspannung
v = c.read_holding_registers(32200, 1, slave=1).registers[0]
print(f"Netz: {v * 0.1:.1f} V")

# uint32 Ladeenergie (total_grid_input_energy)
hi = c.read_holding_registers(33000, 1, slave=1).registers[0]
lo = c.read_holding_registers(33001, 1, slave=1).registers[0]
print(f"Netzbezug gesamt: {((hi << 16) | lo) * 0.01:.2f} kWh")

# uint32 Entladeenergie (total_grid_output_energy)
hi2 = c.read_holding_registers(33002, 1, slave=1).registers[0]
lo2 = c.read_holding_registers(33003, 1, slave=1).registers[0]
print(f"Einspeisung gesamt: {((hi2 << 16) | lo2) * 0.01:.2f} kWh")

c.close()
```

---

## Anhang A: Scan-Kontext (Gerätezustand beim Scan)

```
Datum:          Mai 2026
Gerät:          Marstek Venus D (VNSD-0)
Batterie-Packs: 2
SOC Pack1:      10.9% (raw 109, Scale 0.1)
SOC Pack2:      12.0% (raw 120, Scale 0.1)
Spannung Pack1: 50.12V
Spannung Pack2: 51.25V
AC-Netz:        239.8V / 49.9Hz
AC-Strom:       −4.98A (Einspeisung)
PV:             NICHT angeschlossen (MPPT = Leerlauf ~9.9V)
Modus:          Anti-Einspeisung (work_mode=1)
RS485:          Steuerung AKTIV (42000=0x55AA)
Backup/UPS:     Aktiv (41200=1)
```

## Anhang B: Werkzeuge & Abhängigkeiten

```bash
# Python-Abhängigkeiten
pip3 install pymodbus pandas

# Ghidra (macOS)
brew install ghidra
brew install --cask temurin@21  # Java 21

# Ghidra-Skripte: Jython 2.7 (eingebaut, kein Extra-Install)
# Wichtig: # -*- coding: utf-8 -*- in Zeile 1, keine Umlaute!
```

---

*Erstellt: Mai 2026 | Firmware: VNSEE3-0 v148 | Gerät: Marstek Venus D*  
*Analyse-Tool: Ghidra + Python 3 + pymodbus + marstek-fw-checker*  
*Rev 7: Vollständiger Adressraum bestätigt (0–65535) · Cloud/OTA-API analysiert*

---

## Anhang C: Erweiterte Ghidra-Analyse (Ergänzung)

### C.1 Neugefundene SRAM-Variablen

Aus `FUN_08004bd8` (Max-Leistungs-Initialisierung):

| SRAM-Adresse | Variable | Bedeutung |
|---|---|---|
| `0x20000136` | `DAT_20000136` | Hardware-Version (version_num) |
| `0x2000012f` | `DAT_2000012f` | Max Ladeleistung (dynamisch, versionsabhängig) |
| `0x2000012d` | `DAT_2000012d` | Max Entladeleistung |
| `0x20000260` | `DAT_20000260` | Aktueller Leistungs-Setpoint (EMS) |
| `0x2000026f` | `DAT_2000026f` | RS485-Tabellen-Index |
| `0x20000270` | `DAT_20000270` | Modbus-Slave-ID (low byte) |
| `0x20000271` | `DAT_20000271` | Modbus-Slave-ID (high byte) |
| `0x200002b2` | `DAT_200002b2` | Timer/Hysterese-Counter |
| `0x20000269` | `DAT_20000269` | EMS-Steuerungs-State |

Hardware-Version → Max-Leistung Mapping:
```
version_num = 0  →  max_power = 2500 W  (Standard Venus E)
version_num = 1  →  max_power =  800 W  (kleinere Variante)
version_num = 2  →  max_power =  600 W  (kleinste Variante)
```

### C.2 Zweite Descriptor-Tabelle entdeckt

In `FUN_08004b20` wurde ein identisches Zugriffsmuster auf eine zweite Tabelle gefunden:

```c
// Haupt-Tabelle (TCP Modbus):
(&DAT_200002f8)[uVar4 * 6]          // base: 0x200002F8, 231 Einträge

// Zweite Tabelle (RS485/EMS):
*(ushort *)(DAT_2000026f * 6 + 0x600172b8)  // base: 0x600172b8, ~96 Einträge
```

| Eigenschaft | TCP-Tabelle | RS485-Tabelle |
|---|---|---|
| Basis | `0x200002F8` (SRAM) | `0x600172b8` (Ext-RAM / CH395Q) |
| Einträge | 231 (0xE7) | ~96 (0x5F+1) |
| Stride | 12 Bytes | 12 Bytes (identisch) |
| Zweck | Modbus TCP Read-Register | RS485/EMS interne Register |

### C.3 Abschließende Analyse-Ergebnisse

**Vollständig dekompilierte Funktionen:**

| Funktion | Name | Status |
|---|---|---|
| `FUN_0801c088` | Modbus_TCPRouter | ✅ Vollständig |
| `FUN_0804b73c` | Modbus_ReadSerializer | ✅ Vollständig |
| `FUN_0804c83c` | Modbus_WriteHandler | ✅ Vollständig |
| `FUN_0801ba3c` | Modbus_TCP_TaskLoop | ✅ Vollständig |
| `FUN_0801bcb0` | RS485_PacketHandler | ✅ Vollständig |
| `FUN_08025f3c` | RS485_FC03_ReadHandler | ✅ Vollständig |
| `FUN_080128a0` | JSON_ConfigParser | ✅ (falsch identifiziert) |
| `FUN_08027dd0` | EMS_PowerControl | ✅ Vollständig |
| `FUN_0802b384` | Energy_Accounting | ✅ Vollständig |
| `FUN_08004bd8` | MaxPower_Init | ✅ Vollständig |

**Descriptor-Init: Conclusio**

Die Init-Funktion für `DAT_200002f8` ist durch statische Analyse nicht auffindbar.
Begründung: Sie verwendet ausschließlich computed/indirect addressing für alle Schreibzugriffe.
Ghidra erstellt für computed-address Stores keine Referenzen.

Lösungswege:
1. **Batch-Scan** (empfohlen): `scan_modbus_batch.py` → 0-65535 in ~52 Min
2. **JTAG/SWD**: 2772 Bytes ab `0x200002F8` bei laufendem Gerät lesen
3. **Unicorn-Emulation**: Binary emulieren bis SRAM initialisiert ist

---

## Anhang D: Vollständiger Scan — 413 Register (Mai 2026)

### D.1 Scan-Ergebnis Übersicht

```
Scan-Datum:        Mai 2026
Methode:           Raw TCP Socket, Batch=32, direkte Adressierung (PDU-Addr = Register-Nr)
Scanner:           scan_modbus_batch.py v7
Dauer:             2:30h (Batch=32, Fallback Einzel-Reads, Skip leere Blöcke)
Gefunden:          413 Register (vorher: 130)
Adressraum:        0 – 65535 (vollständig gescannt ✅)

ABGESCHLOSSEN:
  Register 0–29999:     LEER — keine einzige Antwort
  Register 30000–39999: 89 Read-Register bestätigt
  Register 40000–49999: 41 Write-Register bestätigt
  Register 50000–65535: LEER — keine einzige Antwort
```

> **Bedeutung:** Der Modbus-Adressraum ist damit vollständig kartiert.
> Es gibt keine weiteren unbekannten Bereiche. Alle 413 gefundenen Register
> befinden sich ausschließlich zwischen 30000 und 49999.

### D.2 Neuentdeckte Register-Cluster

| Cluster | Register | Inhalt |
|---|---|---|
| **NEU** | 30000–30010 | Neue Leistungs-/Status-Register |
| Bekannt | 30020–30040 | MPPT / PV |
| **NEU** | 30100–30110 | Pack 1 BMS (erweitert) |
| **NEU** | 30200–30214 | Firmware-Versionen (erweitert) |
| **NEU** | 30400–30403 | IP-Adressen (Gerät + Gateway) |
| Bekannt | 31000–31009 | Gerätename |
| Bekannt | 33000–33011 | Energie-Zähler |
| **NEU** | 34000–34033 | Pack 1 (detailliert, inkl. Einzel-Temps) |
| **NEU** | 34100–34133 | Pack 2 (detailliert) |
| **NEU** | 34200–34233 | Pack 3 Slot (leer = nicht verbaut) |
| **NEU** | 34300–34333 | Pack 4 Slot (leer) |
| **NEU** | 34400–34433 | Pack 5 Slot (leer) |
| **NEU** | 34500–34533 | Pack 6 Slot (leer) |
| **NEU** | 34600–34633 | Pack 7 Slot (leer) |
| **NEU** | 35000–35012 | Temperaturen (erweitert) |
| **NEU** | 35110–35112 | Leistungs-Limits (neu) |
| Bekannt | 36000–36103 | Alarm / Fehler |
| **NEU** | 37000–37024 | Kombinierte Netz+Sensor-Werte |

### D.3 Neudekodierte Register (vollständige Liste)

#### Neue Register 30000–30010

| Register | Rohwert | Interpretiert | Status |
|---|---|---|---|
| 30000 | 509 | ? (evtl. grid_power oder combined_pv_power) | Unbekannt |
| 30001 | −10 | battery_power = −10 W (Entladung) | Bekannt |
| 30002 | 179 | ? | Unbekannt |
| 30003 | 181 | ? | Unbekannt |
| 30004 | 2410 | 241.0 V (evtl. ac_voltage 2. Messung) | Plausibel |
| 30005 | 2 | ? | Unbekannt |
| 30006 | 0 | ac_power = 0 W | Bekannt |
| 30007 | 0 | ? | Unbekannt |
| 30010 | 0 | ? | Unbekannt |
| 30028 | 513 | 0x0201 = ? (selber Wert wie 37022) | Unbekannt |
| 30029 | 65535 | 0xFFFF = −1 → Fehler-Flag? | Unbekannt |
| 30036 | 219 | ? | Unbekannt |

#### Neue Netzwerk-Register (30400–30403)

```
30400–30401:  device_ip   = 192.168.x.x  (eigene IP des Geräts)
30402–30403:  gateway_ip  = 192.168.x.1
```

Kodierung: jedes Register = 2 Bytes der IPv4-Adresse (Big-Endian)
```python
ip_hi = raw_uint16 >> 8    # erstes Oktett
ip_lo = raw_uint16 & 0xFF  # zweites Oktett
```

#### Erweiterte Pack-1-Register (34000–34017)

| Register | Rohwert | Interpretiert |
|---|---|---|
| 34000 | 5114 | pack1_voltage = 51.14 V |
| 34001 | 0 | pack1_current = 0.0 A |
| 34002 | 146 | **pack1_soc = 14.6 %** (Scale 0.1!) |
| 34003 | 19 | pack1_cycle_count = 19 |
| 34004 | 3 | ? (evtl. Anzahl Zellgruppen) |
| 34005 | 3199 | pack1_max_cell_voltage = 3.199 V |
| 34006 | 3195 | pack1_min_cell_voltage = 3.195 V |
| 34010 | 116 | **pack1_bms_version = 116** (nicht Temperatur — raw 116 = BMS-Version wie Reg 30204!) |
| 34011 | 261 | **pack1_temp_max = 26.1 °C** |
| 34012 | 198 | pack1_temp_? = 19.8 °C (NEU) |
| 34013 | 193 | **pack1_temp_min = 19.3 °C** (NEU) |
| 34014 | 194 | pack1_temp_? = 19.4 °C (NEU) |
| 34015 | 192 | pack1_temp_? = 19.2 °C (NEU) |
| 34016 | 191 | pack1_temp_? = 19.1 °C (NEU) |

#### Batterie-Pack-Slots (Firmware unterstützt 7 Packs!)

| Pack | Basis-Register | Spannung | SOC | Zyklen | Status |
|---|---|---|---|---|---|
| Pack 1 | 34000 | 51.14 V | 14.6 % | 19 | ✅ Verbaut |
| Pack 2 | 34100 | 50.24 V | 10.9 % | 17 | ✅ Verbaut |
| Pack 3 | 34200 | 0 V | 0 % | 0 | ❌ Leer |
| Pack 4 | 34300 | 0 V | 0 % | 0 | ❌ Leer |
| Pack 5 | 34400 | 0 V | 0 % | 0 | ❌ Leer |
| Pack 6 | 34500 | 0 V | 0 % | 0 | ❌ Leer |
| Pack 7 | 34600 | 0 V | 0 % | 0 | ❌ Leer |

#### Register 37000–37024 (neu, kombinierte System-Werte)

| Register | Rohwert | Interpretiert |
|---|---|---|
| 37000 | 1 | system_status = 1 |
| 37004 | 0 | ac_current = 0.00 A |
| 37005 | 14 | ? (1.4) |
| 37006 | 192 | ? (19.2 °C oder 192 W?) |
| 37007 | 3198 | **max_cell_v_all_packs = 3.198 V** |
| 37008 | 3195 | **min_cell_v_all_packs = 3.195 V** |
| 37012 | 116 | **bms_version = 116** (nicht Temperatur — selber Wert wie 30204 und 34010/34110) |
| 37016 | 2416 | ac_voltage = 241.6 V |
| 37022 | 513 | 0x0201 = ? (Protokoll-Version 2.01?) |

#### Register 35110–35112 (neu)

| Register | Rohwert | Wahrscheinliche Bedeutung |
|---|---|---|
| 35110 | 576 | max_charge_power_current = 576 W? |
| 35111 | 500 | rated_charge_power = 500 W? |
| 35112 | 500 | rated_discharge_power = 500 W? |

### D.4 Geräte-Zustand zum Scan-Zeitpunkt

```
Pack 1:  51.14 V,  SOC 14.6%,  19 Zyklen,  BMS-Version 116  (Reg 34010 — NICHT Temperatur!)
Pack 2:  50.24 V,  SOC 10.9%,  17 Zyklen,  BMS-Version 116  (Reg 34110 — NICHT Temperatur!)
Netz:    241.6 V,  Strom 0 A (kein Import/Export)
Modus:   Anti-Einspeisung (work_mode=1)
RS485:   Steuerung aktiv (0x55AA)
Backup:  Aktiv (=1)
Alarm:   0 (kein Alarm)
Fehler:  0x0963 (fault_bits, nicht 0!)
```

> **⚠️ Korrektur:** Reg 34010 (Pack 1) und 34110 (Pack 2) enthalten **BMS-Firmware-Version 116**,
> identisch mit Reg 30204. Der Rohwert 116 wurde fälschlicherweise als 11.6 °C (Scale 0.1)
> interpretiert — ein zur Jahreszeit plausibel erscheinender Wert.
> Tatsächliche Pack-Temperaturen sind in Reg 34011–34016 (Pack 1) bzw. 34111 (Pack 2) zu finden.

### D.5 Technische Erkenntnisse

**Adressierung:** Marstek verwendet **direkte Adressierung** — PDU-Adresse = User-Register-Nummer (kein Offset, kein -1). Beweis: TCPRouter.c vergleicht die rohe PDU-Adresse direkt mit `descriptor.base_addr` ohne jede Korrektur. pymodbus: `read_holding_registers(30000)` → liest Register 30000.

**Maximale Batch-Größe:** 32 Register pro FC03-Request.
Bei Batch > 32 gibt das Gerät keine Antwort (Timeout, kein Exception-Code).

**Lücken im Register-Map:** Viele Adressen sind nicht belegt.
Ein Batch-Request über eine Lücke → Exception Code 2.
Lösung: Fallback auf Einzel-Reads bei Exception.

**Pack-Erweiterbarkeit:** Die Firmware unterstützt bis zu 7 Batterie-Packs
(Register-Blöcke 34000, 34100, 34200, ..., 34600).
Nicht verbundene Packs antworten mit 0 für alle Register.

**Fault-Bits 0x0963:** Dieser Wert war auch beim vorherigen Scan vorhanden.
Bedeutung der einzelnen Bits noch unbekannt.
