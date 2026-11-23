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
- Frühere interne Entwicklungsschritte sind in `Chialya/tempfile/readme/README_13.x.txt` dokumentiert.
- Programmquellcode und Datenverzeichnis 13.6 liegen inzwischen im Hauptrepository.
- Ein formales GitHub-Release bzw. ein Versions-Tag für 13.6 ist noch nicht erstellt.

## Repository-Inhalt

- `README.md`: Ausführliche technische Projektbeschreibung und Funktionsweise von Version 13.6.
- `LICENSE`: Benutzerdefinierte restriktive Lizenz, Version 1.0.
- `CHANGELOG.md`: Öffentliche Versionshistorie.
- `PROJECT_STATUS.md`: Dieser aktuelle Projekt- und Übergabestand.
- `nfqfilter_13.6/`: Programm- und Moduldateien der Version 13.6.
- `nfqfilter.data/`: Konfiguration, Listen und Daten-/Logdateien.

## Dokumentations- und Prüfgrundlage

Die ausführliche README wurde anhand des extrahierten 13.6-Quellpakets und der
Versionsnotizen `README_13.1.txt` bis `README_13.6.txt` erstellt.

Geprüfter Archivinhalt:
- 17 Python-Dateien im Programmverzeichnis.
- 7 Dateien im Datenverzeichnis einschließlich Konfiguration, Listen und Logs.
- Alle 17 Python-Dateien bestehen `python3 -m py_compile *.py`.
- Im Archiv selbst sind keine Offline-Testdateien enthalten.
- Die Syntaxprüfung ist kein Live-Test der NFQUEUE- oder Firewall-Funktion.

Der Quellcode und das Datenverzeichnis wurden anschließend durch einen GitHub-
Actions-Commit in das Hauptrepository übernommen. Die Dateien sind im aktuellen
Repository-Baum vorhanden. Die mitgelieferte Konfiguration und Daten wurden
nicht im Rahmen der Dokumentation verändert.

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
2. Änderungen an Konfigurationen, Zugangsdaten, privaten IP-Adressen, lokalen
   Pfaden und Laufzeit-/Nutzdaten müssen vor einer Veröffentlichung geprüft werden.
3. Keine Dateien oder Inhalte werden durch Platzhalter ersetzt, nur um das
   Repository zu füllen.
4. Änderungen an Dateien werden über Git-Commits nachvollziehbar dokumentiert.
5. Wichtige, freigegebene Meilensteine werden zusätzlich mit Git-Tags/Releases
   markiert.

## Aktueller offener Arbeitsstand

### Version 13.6

- Quellcode und Datenverzeichnis sind im Hauptrepository vorhanden.
- Die zentrale README wurde ausführlich erweitert und mit dem Quellcode abgeglichen.
- Die historischen Versionsnotizen liegen weiterhin im temporären Repository
  `Chialya/tempfile` im Ordner `readme`.
- Die Syntaxprüfung aller 17 Python-Dateien war erfolgreich.
- Ein Live-Test auf dem Zielrouter wurde im Rahmen dieser Prüfung nicht ausgeführt.
- Im Archiv waren keine Offline-Testdateien enthalten.
- Ein formales Release mit Tag und Release-Notizen steht noch aus.

### Nächste Schritte

1. Den Veröffentlichungsinhalt des Datenverzeichnisses nochmals gezielt prüfen
   und den gewünschten Umfang der Konfigurations-, Listen- und Logdateien festlegen.
2. Die README bei späteren Codeänderungen synchron halten.
3. CHANGELOG für den finalen 13.6-Release-Stand vervollständigen.
4. Nach Freigabe Version 13.6 taggen und als GitHub-Release veröffentlichen.

## Übergabe an einen neuen Chat

Zuerst diese Datei lesen. Danach bei Bedarf die tatsächlichen Dateien im Repository,
den Git-Commit-Verlauf und die jeweils betroffenen Quelldateien prüfen.
Diese Statusdatei ersetzt weder den Quellcode noch den Commit-Verlauf.
