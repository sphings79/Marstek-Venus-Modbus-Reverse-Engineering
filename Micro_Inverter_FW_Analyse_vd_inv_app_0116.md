# Marstek Venus D — Micro/Inverter Co-Prozessor Firmware Analyse
## `vd_inv_app_0116_0702_ota_163439.bin`

**Firmware:** v116 (OTA `firmwareType: micro`)  
**Analysedatum:** 04.07.2026  
**Methode:** Statische Analyse (Ghidra + ReVa MCP)  
**Status:** Erstanalyse — alle Schlüssel-Subsysteme identifiziert

---

## 1. Binary-Fingerprint

| Eigenschaft | Wert | Vergleich Control-FW |
|---|---|---|
| Größe | 115.712 B (0x1C400) | 385.024 B |
| Architektur | ARM Cortex-M4F, Thumb-2, LE | identisch |
| Flash-Basis | `0x08000000` | identisch |
| Flash-Ende | `0x0801C3FF` | `0x0805E1FF` |
| Initial SP | `0x20009A70` (~40 KB SRAM) | `0x2001F318` (~128 KB) |
| Reset Handler | `0x080042AD` | `0x08004A71` |
| Funktionen | 436 | 1.600 |
| Strings | 251 | ~800+ |
| Compiler | RVDS/Keil ARM | GCC (vermutlich) |
| RTOS | FreeRTOS (heap_4) | FreeRTOS (heap_4) |
| FP-Port | `ARM_CM4F` (FPU aktiv) | ARM_CM4F |
| Crypto | — (keine mbedTLS) | mbedTLS 2.28.10 |
| WiFi/TCP | — (nicht vorhanden) | FC41D WiFi, Modbus TCP |

**Wesentliche Unterschiede zur Control-FW:**
- Kein WiFi-Stack, kein TCP/IP, kein Modbus TCP — die Micro-MCU kommuniziert ausschließlich über CAN-Bus und RS485/UART
- Kein mbedTLS — keine Verschlüsselung, keine Cloud-Anbindung
- Deutlich kleiner (~30% der Control-FW)
- Verwendet RVDS/Keil Compiler statt GCC
- Enthält eigenen Bootloader-Thunk-Bereich (`0x10000xxx`)

---

## 2. Speicher-Layout

```
Flash (0x08000000 – 0x0801C3FF):
  0x08000000 – 0x080001FF   IVT (Interrupt-Vektortabelle)
  0x08000200 – 0x080009FF   Thunks zu Bootloader (0x10000xxx)
  0x08000A00 – 0x0800B3FF   Peripherie-Treiber (CAN, UART, ADC, GPIO, Flash, PWM)
  0x0800B400 – 0x0800B5FF   FreeRTOS Task-Erstellung
  0x0800B600 – 0x0800C8FF   Firmware-Update (UART Ymodem + CAN)
  0x0800C900 – 0x0800D7FF   Debug/Diagnose-Ausgabe (Sensor-Dump)
  0x0800D800 – 0x0800DFFF   Utility-Funktionen
  0x0800E000 – 0x0800E9FF   Hex-Konvertierung, FreeRTOS Assert-Handler
  0x0800EA00 – 0x0800EDFF   Initialisierung, CAN-Filter-Setup
  0x0800EE00 – 0x08014FFF   Wechselrichter-Regelung (FP-intensiv)
  0x08015000 – 0x0801C3FF   FreeRTOS Kernel + Task-Schleifencode

SRAM-Regionen (identifiziert):
  0x20000000 – 0x200003FF   Task-Handles, Konfiguration, Kalibrierdaten
  0x20000400 – 0x200004FF   Betriebsparameter, Flags, Modi
  0x20000D00 – 0x20000EFF   ADC-Messwerte (Roh + kalibriert)
  0x20001400 – 0x200019FF   Debug-Counter, Fehlerlog, Energiezähler
  0x20003400 – 0x200038FF   FW-Update-Puffer, CAN-Empfangspuffer
  0x20003900 – 0x200039FF   BMS-Daten (via CAN empfangen)
  0x20003D00 – 0x20003EFF   Betriebsmodi, Konfiguration
```

---

## 3. FreeRTOS Task-Architektur

`FUN_0800b420` = Task-Creator, `FUN_08013998` = `xTaskCreate`

| Task | Priorität | Stack | Entry-Point | Funktion |
|---|---|---|---|---|
| `vtask_led` | 16 (höchste) | 512 B | `0x080163E8` | LED-Statusanzeige |
| `vtask_time` | 15 | 1 KB | `0x080164C8` | Zeitgeber/RTC |
| `vtask_modbus` | 14 | 512 B | `0x08016424` | RS485-Modbus-Kommunikation |
| `vtask_shell` | 9 | 2 KB | `0x0801643C` | Debug-CLI (UART) |
| `vtask_prt` | 8 | 1 KB | `0x08016430` | Debug-Ausgabe |
| `vtask_can_receive` | 7 | 1 KB | `0x080163E0` | CAN-Empfang |
| `vtask_can` | 6 | 1 KB | `0x080163D0` | CAN-Senden |
| `IDLE` | 0 | 512 B | `0x08012FD0` | FreeRTOS Idle |

**Anmerkung:** Die Task-Entry-Points ab `0x08016xxx` liegen in einem zusammenhängenden FP-Codeblock für die Wechselrichter-Regelung. Ghidra hat Schwierigkeiten mit der Funktionsgrenzen-Erkennung dort, da die Regelschleifen stark ineinandergreifen.

---

## 4. Kommunikationsarchitektur

### 4.1 CAN-Bus (Hauptkommunikation)

CAN-Peripherie: `0x40006400` (CAN1, STM32F4)

**CAN-Filter (konfiguriert in `FUN_0800eb88`):**

| Filter | ID | Maske | Matches | Protokoll |
|---|---|---|---|---|
| 1 | `0x4000` | `0xFF00` | `0x40xx` | EMS→Inverter Befehle |
| 2 | `0x4100` | `0xFF00` | `0x41xx` | Inverter→EMS Antworten |
| 3 | `0x1801AA01` | `0x1FF0FFFF` | `0x180xAA01` | BMS CAN-Protokoll |

### 4.2 BMS CAN-Protokoll (Extended Frame, 29-bit)

Parser: `FUN_080018e8` — PF-Byte (Bits 16–19 der CAN-ID) bestimmt den Nachrichtentyp.

| CAN-ID | PF | Byte 0–1 | Byte 2–3 | Byte 4–5 | Byte 6–7 |
|---|---|---|---|---|---|
| `0x1801AA01` | 1 | bat_vol (u16) | bat_cur (i16) | max_temp (i16) | soc (u16) |
| `0x1802AA01` | 2 | cap (u16) | ? | ? | ? |
| `0x1803AA01` | 3 | charge_u (u16) | charge_i (u16) | discharge_i (u16) | ? |
| `0x1804AA01` | 4 | err (u32) | warn (u32) |

**SRAM-Mapping der BMS-Daten:**

| SRAM-Adresse | Variable | Typ | Inhalt |
|---|---|---|---|
| `0x2000397B` | bat_vol | uint16 | BMS Batteriespannung |
| `0x2000397D` | bat_cur | int16 | BMS Batteriestrom |
| `0x2000397F` | max_temp | int16 | BMS Max-Temperatur |
| `0x20003981` | soc | uint16 | State of Charge |
| `0x20003983` | cap | uint16 | Kapazität |
| `0x2000398A` | sleep_flag | byte | BMS Sleep-Anforderung |
| `0x2000398B` | charge_u | uint16 | Ladespannungs-Sollwert |
| `0x2000398D` | charge_i | uint16 | Ladestrom-Limit |
| `0x2000398F` | discharge_i | uint16 | Entladestrom-Limit |
| `0x20003991` | charge_req | byte | Ladeanforderung (Flag) |
| `0x20003992` | force_charge_req | byte | Zwangsladung (Flag) |
| `0x20003993` | err | uint32 | BMS Fehlerbitmask |
| `0x20003997` | warn | uint32 | BMS Warnbitmask |

### 4.3 EMS↔Inverter internes CAN-Protokoll (Standard Frame, 11-bit)

Dispatcher: `FUN_08001940` (1.168 Bytes, 269 Zeilen — größte Funktion)

CAN-ID-Format: `0x40xx` (EMS→INV) / `0x41xx` (INV→EMS), wobei `xx` = Command-ID

#### Befehle EMS → Inverter:

| CMD | Hex | Beschreibung | Daten |
|---|---|---|---|
| Set Power | 0x01 | Leistungssollwert setzen | int→float Wandlung |
| Enable/Disable | 0x02 | Wechselrichter ein/aus | 0=aus, 1=ein |
| Max Discharge Power | 0x03 | Max. Entladeleistung | Limit (capped 2500W) |
| Max Charge Power | 0x04 | Max. Ladeleistung | Limit (capped 2500W) |
| Unknown Flag | 0x05 | Internes Flag setzen | DAT_2000043c=1 |
| Sleep Mode | 0x06 | Schlafmodus | DAT_200004a4=1 |
| Address Assign | 0x07 | CAN-Adresse zuweisen | Adresse+1 |
| Config Block | 0x16 | Konfigurationsdaten | 8 Bytes → 0x20003EA7 |
| Factory Test Enter | 0x50 | Werkstestmodus | 0=exit, 1=enter |
| FW Update Trigger | 0x51 | Firmware-Update starten | — |
| FW Update Phase | 0x52 | Update-Phase setzen | 1/2/3 → Step 2/3/4 |
| FW Update Complete | 0x53 | Update abschließen | Step=5 |
| FW Update Finalize | 0x55 | Update finalisieren | Step=6 |
| Set Power (Factory) | 0x56 | Leistung im Werksmodus | Power-Wert |
| Backup Mode | 0x57 | Notstrom ein/aus | 1=ein, 0=aus |
| Set Power (Battery) | 0x58 | Leistung im Bat-Modus | Power-Wert |
| Start FW Update | 0x60 | FW-Update initiieren | Update-Typ |
| FW Update Sequence | 0xC1 | Update-Sequenz starten | Step=1 |
| Debug Mode | 0xC2 | Debug ein/aus | 1→Level 2, else→1 |
| CAN Queue Data | 0xC3 | Daten an CAN weiterleiten | bis 8 Bytes |
| Flash Program | 0xCE | Flash-Programmierung | Typ 0=Init, 1=Data, 2=Verify |

#### Antworten Inverter → EMS:

| CMD | Hex | Beschreibung | Daten |
|---|---|---|---|
| Data Block | 0x10 | 48 Bytes Betriebsdaten | ab 0x200038E8 |
| Status | 0x11 | 8 Bytes Statusinfo | ab 0x20000440 |
| Version Info | 0x12 | FW-Versionsdaten | 6 Bytes |
| Calibration | 0x13 | Kalibrierdaten | 4 Bytes |
| Flash ID | 0x54 | Flash-Chip-Identifikation | — |
| Version/Flash | 0xCB | Erweiterte Version/Flash-Info | 8 Bytes |

**Wichtige Erkenntnisse:**
- **Max-Power-Cap 2500W** (0x9C4) — bestätigt Venus-D-Hardware
- `DAT_20003E04` = work_mode: `0x00`=Normal, `0x01`=Test, `0x04`=Update, `0x0C`=Factory
- `DAT_2000043E` = Firmware-Update-Step-Counter (1–7)
- `DAT_200004AD` = max_discharge_power, `DAT_200004AB` = max_charge_power (beide ≤2500)

---

## 5. ADC-Sensor-Map (Inverter-Messwerte)

Aus Debug-Funktion `FUN_0800cc40` extrahiert.

### 5.1 Roh-ADC-Werte (int16, SRAM `0x20000E44`–`0x20000E62`)

| SRAM | Variable | Typ | Beschreibung |
|---|---|---|---|
| `0x20000E44` | grid_vol | int16 | Netzspannung (Roh-ADC) |
| `0x20000E46` | offgrid_vol | int16 | Notstrom-Spannung (Roh) |
| `0x20000E48` | out_vol | int16 | Ausgangsspannung (Roh) |
| `0x20000E4A` | grid_vref1 | int16 | Netz-Referenz 1 |
| `0x20000E4C` | grid_vref3 | int16 | Netz-Referenz 3 |
| `0x20000E4E` | grid_vref4 | int16 | Netz-Referenz 4 |
| `0x20000E50` | grid_cur | int16 | Netzstrom (Roh-ADC) |
| `0x20000E52` | offgrid_cur | int16 | Notstrom-Strom (Roh) |
| `0x20000E54` | highv_vol | int16 | DC-Bus-Spannung (Roh) |
| `0x20000E56` | bat_cur | int16 | Batteriestrom (Roh) |
| `0x20000E58` | bat_cur_df | int16 | Batteriestrom diff (Roh) |
| `0x20000E5A` | bat_vol | int16 | Batteriespannung (Roh) |
| `0x20000E5C` | vac_offset | int16 | AC-Spannungs-Offset |
| `0x20000E5E` | iac_offset | int16 | AC-Strom-Offset |
| `0x20000E60` | ntc_rad1 | int16 | NTC Radiator 1 (Roh) |
| `0x20000E62` | ntc_rad2 | int16 | NTC Radiator 2 (Roh) |

### 5.2 Kalibrierte Float-Werte (SRAM `0x20000DE0`–`0x20000E34`)

| SRAM | Variable | Typ | Beschreibung |
|---|---|---|---|
| `0x20000DE0` | grid_vol | float | Netzspannung (V, kalibriert) |
| `0x20000DE4` | grid_cur | float | Netzstrom (A, kalibriert) |
| `0x20000DEC` | highv_vol | float | DC-Bus-Spannung (V) |
| `0x20000DF0` | out_vol | float | Ausgangsspannung (V) |
| `0x20000DF4` | bat_vol | float | Batteriespannung (V) |
| `0x20000DF8` | bat_cur | float | Batteriestrom (A) |
| `0x20000DFC` | bat_cur_df | float | Batteriestrom diff (A) |
| `0x20000E04` | offgrid_cur | float | Notstrom-Strom (A) |
| `0x20000E08` | offgrid_vol | float | Notstrom-Spannung (V) |
| `0x20000E0C` | highv_notch_vol | float | DC-Bus Notch-gefiltert (V) |
| `0x20000E10` | bat_vol_avg | float | Batteriespannung Mittelwert |
| `0x20000E14` | bat_cur_avg | float | Batteriestrom Mittelwert |
| `0x20000E20` | vac_offset | float | AC-Spannungs-Offset (kal.) |
| `0x20000E24` | iac_offset | float | AC-Strom-Offset (kal.) |
| `0x20000E2C` | ntc_temp | float | Temperatur allgemein (°C) |
| `0x20000E30` | ntc_inv | float | Inverter-Temperatur (°C) |
| `0x20000E34` | ntc_mppt | float | MPPT-Temperatur (°C) |

### 5.3 Weitere Kalibrier-/Statuswerte

| SRAM | Variable | Beschreibung |
|---|---|---|
| `0x20000338` | g_offset_vol | Globaler Spannungs-Offset (float) |
| `0x20000344` | real_offset_vol | Realer Spannungs-Offset (float) |
| `0x200002A4` | inverter_run_state | Inverter-Zustandsmaschine |
| `0x200002A5` | llc_run_state | LLC-Wandler-Zustand |
| `0x200002A8` | ctl_state | Control-Hauptzustand |
| `0x200004A6` | bat_mode | Batteriemodus |
| `0x200004AF` | grid_standand | Netzstandard-Code |
| `0x2000030C` | max_power | Max. Leistung (float) |
| `0x20000310` | min_power | Min. Leistung (float) |
| `0x200019F4` | err1 | Fehlerregister 1 (hex) |
| `0x200019F8` | err2 | Fehlerregister 2 (hex) |
| `0x200019FC` | war1 | Warnregister (hex) |

---

## 6. Hardware-IO-Map (GPIO)

Aus Debug-Strings in den IO-Show/Test-Funktionen extrahiert:

| GPIO-Bezeichner | Funktion | Beschreibung |
|---|---|---|
| `LED0` | Status-LED | Betriebs-/Fehler-LED |
| `IO_RELAY_GRID` | Netzrelais | Grid-Kontakt (Netzverbindung) |
| `IO_RELAY_OFFGRID` | Notstrom-Relais | Off-Grid-Kontakt (UPS) |
| `IO_FAULT_RESET` | Fehler-Reset | Hardware-Fault-Reset-Pin |
| `IO_AUX_GRID` | Hilfs-Netz | Auxiliary Grid-Kontakt |
| `IO_AUX_BAT` | Hilfs-Batterie | Auxiliary Batterie-Kontakt |
| `IO_FAULT_HARDWARE` | HW-Fehler | Hardware-Fault-Eingang |
| `IO_FAULT_HARDWARE_IGRID_1` | Netzstrom-Fehler 1 | Überstromschutz Netz Ch1 |
| `IO_FAULT_HARDWARE_IGRID_2` | Netzstrom-Fehler 2 | Überstromschutz Netz Ch2 |
| `IO_FAULT_HARDWARE_VBUS` | DC-Bus-Fehler | Überspannungsschutz DC-Bus |
| `IO_FAULT_HARDWARE_IBAT_1` | Batteriestrom-Fehler 1 | Überstromschutz Batterie Ch1 |
| `IO_FAULT_HARDWARE_IBAT_2` | Batteriestrom-Fehler 2 | Überstromschutz Batterie Ch2 |

---

## 7. Debug-Shell (UART-CLI)

Die Firmware enthält eine vollständige Debug-Shell über UART (`vtask_shell`), geschützt mit Passwort.

### Shell-Befehle (aus String-Analyse):

| Befehl | Beschreibung |
|---|---|
| `version` | Software-/Boot-Version anzeigen |
| `log_data` | Sensor-Daten loggen |
| `log_list` | Log-Einträge auflisten |
| `log_err` | Fehlerlog anzeigen |
| `log_clear` | Log löschen |
| `log_open` | Log aktivieren |
| `rtos_status` | FreeRTOS Task-Status |
| `io_show` | GPIO-Status anzeigen |
| `io_set` | GPIO manuell setzen |
| `fan_set` | Lüfter-Steuerung |
| `set_power` | Leistung setzen |
| `show_power` | set/max/low_power anzeigen |
| `power_cfg` | Leistungskonfiguration |
| `pf_power` | Power Factor Einstellung |
| `bat_mode` | Batteriemodus setzen |
| `backup_mode` | Notstrom-Modus |
| `par_mode` | Parallelmodus |
| `set_mode` | Betriebsmodus wählen |
| `sr_set` | Synchron-Gleichrichtung Duty |
| `dac_high` / `dac_low` | DAC-Ausgabe |
| `alarm` | Alarmstatus |
| `update` | Selbst-Update (UART) |
| `update_bms` | BMS über CAN updaten |
| `update_bms2` | BMS über RS485 updaten |
| `reset` | System-Reset |
| `reset_memory` | Speicher zurücksetzen |
| `old_ate` | ATE-Testmodus (alt) |
| `test` / `test_1` | Testfunktionen |
| `clear` | Konsole löschen |
| `help` | Hilfe anzeigen |

### Version-Strings:
- `SOFT_VERSION:%d` — Firmware-Version (Wert: 116)
- `BOOT_VERSION:%d` — Bootloader-Version
- `hardware %d ,set_ver: %d` — Hardware-Revision + Set-Version

---

## 8. Wechselrichter-Regelung

### Zustandsmaschine:

```
ctl_state (0x200002A8) — Hauptsteuerung
    ↳ llc_run_state (0x200002A5) — LLC-Wandler (DC-DC)
    ↳ inverter_run_state (0x200002A4) — H-Brücke (DC-AC)
```

### Regelungsbausteine:
- **PID-Regler** mit `kp`, `ki` (Leistungs- und Stromregelung)
- **PR-Regler** (Proportional-Resonant) mit `kp`, `kr` (Netzstrom-Regelung)
- **RMS-Berechnung** via FP-Summierung (`g_irms_struct`)
- **Nulldurchgangserkennung** (`zcd` = Zero Crossing Detector)
- **Notch-Filter** für DC-Bus (`highv_notch_vol`)
- **Synchron-Gleichrichtung** (`sr_duty`)

### Betriebsmodi (`work_mode` @ `DAT_20003E04`):

| Wert | Modus | Beschreibung |
|---|---|---|
| 0x00 | Normal | Normalbetrieb |
| 0x01 | Test | Werkstestmodus |
| 0x04 | Update | Firmware-Update aktiv |
| 0x0C | Factory | Fabrikmodus (12) |

---

## 9. Firmware-Update-Mechanismus

Die Micro-MCU unterstützt drei Update-Pfade:

| Pfad | Interface | Beschreibung |
|---|---|---|
| Selbst-Update | UART (Ymodem) | Eigene FW über serielle Konsole |
| BMS über CAN | CAN-Bus | BMS-FW an BMS-MCU weiterleiten |
| BMS über RS485 | RS485/UART | BMS-FW über RS485 flashen |

**Update-Sequenz über CAN (vom EMS-Controller gesteuert):**
1. `0xC1` → Step 1 (Initialisierung)
2. `0x60` → Update-Typ setzen, work_mode=0x04
3. `0x51` → Update triggern
4. `0x52(1)` → Step 2, `0x52(2)` → Step 3, `0x52(3)` → Step 4
5. `0x53` → Step 5 (Verifikation)
6. `0x55` → Step 6 (Finalisierung)
7. `0xCE` → Flash-Daten schreiben (Typ 0=Init, 1=Data, 2=Verify)

---

## 10. Bootloader-Thunks

Die Firmware enthält Thunks zu externen Funktionen im Bereich `0x10000xxx`:

| Thunk-Adresse | Ziel | Vermutete Funktion |
|---|---|---|
| `0x08000960` | `0x10000B58` | Power-Regler-Funktion (3 Aufrufe) |
| `0x08000974` | `0x100009E8` | Inverter Stop/Start (2 Aufrufe) |
| `0x0800097E` | `0x10000160` | Float-Verarbeitung (3 Aufrufe) |
| `0x08000988` | `0x100069E4` | Enable/Disable-Funktion (2 Aufrufe) |
| `0x080009BA` | `0x10006874` | Einmalige Init-Funktion |
| `0x08000A1E` | `0x10000124` | Einmalige Init-Funktion |

Diese Funktionen liegen im System-Memory oder Bootloader-Bereich und werden beim Start in den SRAM gemapped.

---

## 11. Zusammenfassung & Relevanz für Modbus-Integration

### Was die Micro-MCU liefert:

Die EMS-Control-MCU (die den Modbus-TCP-Stack hat) liest über den internen CAN-Bus die folgenden Werte aus der Micro-MCU ab (CMD `0x10`/`0x11`), die dann als Modbus-Register exponiert werden:

| Micro-MCU Variable | Vermutetes Modbus-Register | Control-FW Name |
|---|---|---|
| grid_vol | 32200 | ac_voltage |
| grid_cur | — | ac_current |
| highv_vol | — | dc_bus_voltage |
| bat_vol | — | inverter_bat_voltage |
| bat_cur | — | inverter_bat_current |
| offgrid_vol | 32300 | ac_offgrid_voltage |
| offgrid_cur | 32301 | ac_offgrid_current |
| ntc_temp | — | temp_1..5 |
| ntc_inv | — | inverter_temperature |
| ntc_mppt | — | mppt_temperature |
| soc (BMS) | 34002 | battery_soc |
| err1/err2 | — | error_bitmask |
| war1 | — | warning_bitmask |
| work_mode | — | work_mode |
| grid_standand | — | grid_standard |
| max_power/min_power | — | max_power_limit |

### Offene Fragen für weitere Analyse:
1. **48-Byte Datenblock** (CMD `0x10`, SRAM `0x200038E8`): Welche Werte enthält dieser Block? Dies ist vermutlich das Haupt-Telemetrie-Paket
2. **8-Byte Status** (CMD `0x11`, SRAM `0x20000440`): Format des Statusblocks
3. **CAN-ID `0x40xx` vs `0x41xx`**: Bestätigung der Richtung (Request/Response)
4. **Fehlercodes**: Bitmask-Dekodierung von err1/err2/war1
5. **grid_standand** Werte: Zuordnung zu Netzstandards (VDE-AR-N 4105, EN 50549, etc.)
6. **Bootloader-Funktionen**: Was machen die Thunks bei `0x10000xxx`?

---

*Erstellt via Ghidra + ReVa MCP — Statische Analyse ohne Live-Gerät*
