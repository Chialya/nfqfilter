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
- Geplante/erste öffentliche Version: **13.6**
- Die Versionsnummerierung wird aus der bisherigen Entwicklung übernommen.
- Frühere interne Entwicklungsschritte werden nicht nachträglich vollständig rekonstruiert.
- Quellcode und Release-Paket 13.6 sind noch nicht im öffentlichen Repository veröffentlicht.

## Repository-Inhalt

- `README.md`: Projektbeschreibung und Plattformhinweise.
- `LICENSE`: Benutzerdefinierte restriktive Lizenz, Version 1.0.
- `CHANGELOG.md`: Öffentliche Versionshistorie.
- `PROJECT_STATUS.md`: Dieser aktuelle Projekt- und Übergabestand.

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

- Das Repository wurde angelegt und ist öffentlich.
- README, Lizenz und Changelog sind vorhanden.
- Das Archiv `nfqfilter_13.6+data.tgz` wurde in der ChatGPT-Dateibibliothek
  gefunden, lässt sich derzeit aber nicht materialisieren oder auslesen.
- Daher konnte der Quellcode noch nicht geprüft oder hochgeladen werden.
- Die Ursache des Dateizugriffsfehlers ist ungeklärt; ein Nutzungslimit ist nicht
  als Ursache bestätigt.

### Nächste Schritte

1. Zugriff auf eine lesbare Kopie des vollständigen Quellcode-Archivs herstellen.
2. Archivinhalt prüfen und Quellcode von privaten Konfigurationen und Laufzeitdaten
   trennen.
3. Veröffentlichungsumfang gemeinsam festlegen.
4. Installations- und Konfigurationshinweise ergänzen.
5. Geprüften Quellcode committen und Version 13.6 als GitHub-Release markieren.

## Übergabe an einen neuen Chat

Zuerst diese Datei lesen. Danach bei Bedarf die tatsächlichen Dateien im Repository,
den Git-Commit-Verlauf und die jeweils betroffenen Quellcodedateien prüfen.
Diese Statusdatei ersetzt weder den Quellcode noch den Commit-Verlauf.
