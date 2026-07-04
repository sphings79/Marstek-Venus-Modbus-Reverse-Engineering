Dieses Projekt dokumentiert die Reverse-Engineering-Analyse der
Marstek Venus D Firmware für die Home Assistant Integration
marstek_venus_modbus.

Kontext:
- Gerät: Marstek Venus D (VNSD-0), STM32 ARM Cortex-M, FreeRTOS, 6 Batterie-Packs
- Firmware: VNSD-0_app_1492 v149.2 (Juli 2026)
- Modbus TCP Port 502, Register direkt adressiert (PDU-Adresse = Registernummer)
- Schlüssel-Erkenntnis: battery_soc (Reg 34002) hat Scale 0.1!
- RS485-Steuerung: Reg 42000 = 0x55AA nötig für Write-Betrieb
- Descriptor-Tabelle wird runtime-aufgebaut (nicht statisch im Flash)

Alle Dokumentationsdateien, Scan-CSVs und Skripte sind in der
Knowledge Base verfügbar.
