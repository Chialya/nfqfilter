# NFQfilter – Projektstatus

Stand: 2026-11-23

Diese Datei ist die zentrale Übergabe für neue Arbeits-Chats. Sie beschreibt den
zuletzt bestätigten Projektstand und verweist auf die versionierten Änderungen
im GitHub-Repository.

## Projekt

- **Repository:** https://github.com/Chialya/nfqfilter
- **Zweck:** Python-basierte Paketfilterung über Netfilter Queue (NFQUEUE).
- **Zielplattform:** Ubiquiti UniFi Gateways.
- **Nachweislich getestet:** UCG-Ultra und UXG-Lite.
- **Version 13.x:** Entwickelt für Debian 12.
- **Kompatibilität:** Andere UniFi-Geräte und Debian-basierte Systeme sind nicht bestätigt.

## Versions- und Veröffentlichungsstand

- Aktuelle Entwicklungsbasis: **13.6**
- Vorgesehene erste öffentliche Version: **13.6**
- Die Versionsnummerierung wird aus der bisherigen Entwicklung übernommen.
- Frühere interne Entwicklungsschritte sind in `tempfile/readme/README_13.x.txt` dokumentiert.
- **Der Programmquellcode und das Release-Paket 13.6 sind noch nicht im Hauptrepository veröffentlicht.**

## Repository-Inhalt

- `README.md`: Ausführliche technische Projektbeschreibung und Funktionsweise von Version 13.6.
- `LICENSE`: Benutzerdefinierte restriktive Lizenz, Version 1.0.
- `CHANGELOG.md`: Öffentliche Versionshistorie.
- `PROJECT_STATUS.md`: Dieser aktuelle Projekt- und Übergabestand.

## Dokumentationsgrundlage

Die ausführliche README wurde anhand des extrahierten 13.6-Quellpakets und der
Versionsnotizen `README_13.1.txt` bis `README_13.6.txt` erstellt.

Geprüfter Archivinhalt:
- 17 Python-Dateien im Programmverzeichnis.
- 7 Dateien im Datenverzeichnis einschließlich Konfiguration, Listen und Logs.
- Alle 17 Python-Dateien bestehen `python3 -m py_compile *.py`.
- Im Archiv selbst sind keine Offline-Testdateien enthalten.
- Die Syntaxprüfung ist kein Live-Test der NFQUEUE- oder Firewall-Funktion.

Die Beispieldaten und die individuelle Laufzeitkonfiguration sind nicht Teil
des Hauptrepository-Commits. Die README beschreibt die Konfigurationsstruktur,
ohne persönliche API-Zugangsdaten oder lokale Betriebswerte zu übernehmen.

## Festgelegte Lizenzabsichten

- Private, nicht kommerzielle Nutzung ist erlaubt.
- Änderungen für den eigenen privaten Gebrauch sind erlaubt.
- Weitergabe und Veröffentlichung von Quellcode oder veränderten Fassungen sind ohne schriftliche Zustimmung nicht erlaubt.
- Kommerzielle Nutzung ist nicht erlaubt.
- Urheberrechts- und Lizenzhinweise müssen erhalten bleiben.
- Verweise und Links auf das Originalprojekt sind erlaubt.

Hinweis: Die Lizenz ist ein eigener Entwurf und wurde nicht juristisch geprüft.
Der Wortlaut in `LICENSE` ist maßgeblich für den derzeitigen Repository-Stand.

## Arbeitsregeln

1. Die bestehende Filterlogik und der Quellcode werden nicht ohne ausdrückliche
   Zustimmung funktional verändert.
2. Vor der Veröffentlichung des Quellcodes werden Konfigurationen, Zugangsdaten,
   private IP-Adressen, lokale Pfade und Laufzeit-/Nutzdaten geprüft.
3. Keine Dateien oder Inhalte werden durch Platzhalter ersetzt, nur um das
   Repository zu füllen.
4. Änderungen an Dateien werden über Git-Commits nachvollziehbar dokumentiert.
5. Wichtige, freigegebene Meilensteine werden zusätzlich mit Git-Tags/Releases
   markiert.

## Aktueller offener Arbeitsstand

### Veröffentlichung von Version 13.6

- Das Archiv `nfqfilter_13.6+data.tgz` aus `Chialya/tempfile` wurde über einen
  GitHub-Actions-Artefaktlauf extrahiert und lokal geprüft.
- Die technische Dokumentation in `README.md` wurde erweitert und committed.
- Der Programmquellcode wurde noch nicht in das Hauptrepository übernommen.
- Vor der Veröffentlichung ist eine separate Prüfung des Veröffentlichungsumfangs
  erforderlich: Programmdateien, Beispieldaten, persönliche Konfiguration,
  Laufzeitdaten und Logs müssen bewusst voneinander getrennt werden.
- Die Versionsnotizen im Ordner `readme` des temporären Repositories bleiben
  historische Dokumentationsgrundlage.

### Nächste Schritte

1. Programmdateien und Datenverzeichnis getrennt auf Veröffentlichungsfähigkeit prüfen.
2. Veröffentlichungsumfang und Umgang mit den vorhandenen Logs/Listen festlegen.
3. Geprüften Quellcode in das Hauptrepository übernehmen.
4. Release-Paket, Versionshistorie und GitHub-Release für 13.6 erstellen.

## Übergabe an einen neuen Chat

Zuerst diese Datei lesen. Danach bei Bedarf die tatsächlichen Dateien im Repository,
den Git-Commit-Verlauf und die jeweils betroffenen Quelldateien prüfen.
Diese Statusdatei ersetzt weder den Quellcode noch den Commit-Verlauf.
