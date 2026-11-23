# NFQfilter 13.6

NFQfilter ist ein Python-basierter Zusatzfilter für ausgewählte eingehende TCP-Verbindungen auf Ubiquiti-UniFi-Gateways. Er ergänzt die vorhandene Gateway-Firewall um eine quelladressbezogene Prüfung mit DNS/PTR-Auswertung, optionaler AbuseIPDB-Abfrage sowie mehreren zeit- und ereignisabhängigen Sperrmechanismen.

NFQfilter ersetzt **nicht** die UniFi-Firewall. Die regulären Firewall- und Weiterleitungsentscheidungen bleiben bestehen. NFQfilter wird zusätzlich in den Paketpfad eingebunden und entscheidet für die von ihm erfassten TCP-SYN-Pakete, ob diese angenommen oder verworfen werden.

> **Versionsstand:** Diese Dokumentation beschreibt den Quellcode der Version 13.6. Sie ist keine Installationsfreigabe für beliebige UniFi-Geräte. Als Zielsysteme sind UCG-Ultra und UXG-Lite dokumentiert; die 13.x-Entwicklung basiert auf Debian 12. Andere Plattformen sind nicht bestätigt.

## Inhaltsverzeichnis

- [1. Ziel und Grundprinzip](#1-ziel-und-grundprinzip)
- [2. Paketfluss und Firewall-Anbindung](#2-paketfluss-und-firewall-anbindung)
- [3. Reihenfolge der Filterentscheidungen](#3-reihenfolge-der-filterentscheidungen)
- [4. DNS- und PTR-Prüfung](#4-dns--und-ptr-prüfung)
- [5. AbuseIPDB](#5-abuseipdb)
- [6. IPv4- und IPv6-Verhalten](#6-ipv4--und-ipv6-verhalten)
- [7. SYN-Erkennung und dynamische Einzel-IP-Sperren](#7-syn-erkennung-und-dynamische-einzel-ip-sperren)
- [8. Netzbasierte Angriffserkennung](#8-netzbasierte-angriffserkennung)
- [9. Datenhaltung und Cache-Persistenz](#9-datenhaltung-und-cache-persistenz)
- [10. Konfiguration und Verzeichnisstruktur](#10-konfiguration-und-verzeichnisstruktur)
- [11. Protokollierung](#11-protokollierung)
- [12. Start, Stop und Fehlerverhalten](#12-start-stop-und-fehlerverhalten)
- [13. Optionale Kernel-Funktionen](#13-optionale-kernel-funktionen)
- [14. Installation und Versionswechsel](#14-installation-und-versionswechsel)
- [15. Grenzen und Sicherheitsaspekte](#15-grenzen-und-sicherheitsaspekte)
- [16. Aufbau des Quellcodes](#16-aufbau-des-quellcodes)

## 1. Ziel und Grundprinzip

Der Filter soll eingehende Verbindungsversuche zu ausgewählten Diensten eines internen Servers anhand mehrerer voneinander unabhängiger Kriterien bewerten. Dazu gehören:

- statische IPv4- und IPv6-Whitelists,
- dynamische Freigabe- und Sperrentscheidungen eines externen Helper-Dienstes,
- Erkennung auffälliger Quellen anhand ihrer PTR-Domain,
- optionale Bewertung der Quell-IP durch AbuseIPDB,
- Erkennung vieler Verbindungsversuche einer einzelnen IP,
- Erkennung verteilter Verbindungsversuche aus einem IPv4-/24-Netz,
- zeitlich begrenzte Sperren mit Speicherung über einen Prozessneustart hinweg.

Die eigentliche Paketentscheidung erfolgt im Userspace durch Python. Der Kernel übergibt passende Pakete über NFQUEUE an den Prozess. Der Prozess setzt anschließend für jedes Paket ein Netfilter-Verdict:

- **ACCEPT:** Paket darf den weiteren Netzwerkpfad durchlaufen.
- **DROP:** Paket wird verworfen.

DNS- und API-Abfragen werden nicht synchron im Paket-Callback ausgeführt. Dafür gibt es Worker-Threads und Warteschlangen. Mehrere zeitgleiche Anfragen derselben Quelladresse beziehungsweise desselben IPv6-/64-Präfixes werden zusammengefasst, damit nicht für jedes SYN eine eigene externe Anfrage ausgelöst wird.

## 2. Paketfluss und Firewall-Anbindung

### 2.1 Einbindung in Netfilter

NFQfilter verwaltet seine eigenen Regeln direkt in:

- IPv4: `iptables -t mangle POSTROUTING`
- IPv6: `ip6tables -t mangle POSTROUTING`

Es werden keine eigenen Regeln in `filter/FORWARD` und keine Änderungen an UniFi-eigenen Firewall-Ketten vorgenommen.

Pro konfiguriertem TCP-Zielport wird jeweils eine eigene NFQUEUE-Regel für IPv4 und IPv6 angelegt. Alle Regeln verwenden ausschließlich **NFQUEUE 0**.

Die Regeln begrenzen den erfassten Verkehr auf:

- TCP,
- neue Verbindungen (`conntrack --ctstate NEW`),
- das initiale SYN-Flag (SYN gesetzt, ACK und RST nicht gesetzt),
- das konfigurierte Zielsystem,
- das konfigurierte Ausgangsinterface,
- die konfigurierten Zielports,
- Quellen, die nicht in den konfigurierten Ausschlussnetzen liegen.

Für IPv4 wird der ursprüngliche Zielport mit `--ctorigdstport` ausgewertet. Das ist wichtig, wenn eine Portweiterleitung das ursprüngliche Ziel bereits per DNAT auf die interne Serveradresse umgeschrieben hat. Bei IPv6 wird `--dport` verwendet.

### 2.2 Eigene Regeln erkennen und verwalten

Die direkten NFQUEUE-Regeln tragen den Kommentar `NFQfilter`. Beim Start entfernt der Rule-Manager nur eigene, entsprechend markierte NFQUEUE-Regeln und erstellt sie anschließend anhand der aktuellen Konfiguration neu.

Zusätzlich wird ein gezielter Übergang von den früheren 13.3-Ketten `NFQ133_POST4` und `NFQ133_POST6` unterstützt. Andere Regeln in POSTROUTING oder UniFi-Ketten werden nicht pauschal gelöscht.

Bei mehreren Ausschlussnetzen pro Adressfamilie verwendet der Rule-Manager ein eigenes ipset:

- `NFQFILTER_EX4` für IPv4,
- `NFQFILTER_EX6` für IPv6.

Bei null oder genau einem Ausschlussnetz wird kein ipset für diese Ausnahmen benötigt.

### 2.3 Queue-Bypass

Die NFQUEUE-Regeln verwenden `--queue-bypass`. Ist kein NFQUEUE-Listener vorhanden, werden die Pakete nicht an einer nicht bedienten Queue festgehalten, sondern passieren diese NFQUEUE-Regel.

Das bedeutet ausdrücklich: **Bei ausgefallenem oder nicht gestartetem NFQfilter entsteht durch diese Regeln kein zusätzlicher NFQfilter-Schutz.** Die reguläre UniFi-Firewall bleibt davon unabhängig zuständig.

## 3. Reihenfolge der Filterentscheidungen

Der Paket-Callback arbeitet in einer festen Reihenfolge. Frühere Entscheidungen können spätere Prüfungen überspringen.

1. **Paket dekodieren:** Quelladresse, Quellport, Zielport und TCP-Flags werden aus dem Paket gelesen. Nicht dekodierbare Pakete werden vom Callback angenommen.
2. **Statische Whitelist:** Ein Treffer führt unmittelbar zu ACCEPT. Die Quelle wird nur für die Hochlaststatistik beobachtet; Scrambler-Prüfung und dynamische Einzel-IP-Sperre werden nicht ausgelöst.
3. **Dynamische Helper-Freigabe:** Eine gültige Freigabe wird berücksichtigt, sofern nicht bereits eine allgemeine DROP-Entscheidung im Cache liegt. Die Einzel-IP-Erkennung bleibt für diese Quelle aktiv.
4. **Dynamische Helper-Sperre:** Eine aktive BAD-Entscheidung führt zu DROP.
5. **IPv4-/24-Erkennung:** Auf den konfigurierten Ports wird geprüft, ob innerhalb des Zeitfensters genügend unterschiedliche IPv4-Adressen desselben /24-Netzes beobachtet wurden.
6. **Einzel-IP-SYN-Flutschutz:** Für konfigurierte Ports wird eine auffällige Zahl unterschiedlicher TCP-Quellports derselben Quell-IP erkannt.
7. **Bereits aktive Einzel-IP-Sperre:** Eine bekannte /32- beziehungsweise /128-Sperre führt bei SYN unmittelbar zu DROP.
8. **Allgemeiner Entscheidungs-Cache:** Ein gültiges DROP wird unmittelbar angewendet. Ein gültiges ACCEPT kann verwendet werden, sofern für den angesprochenen Port keine zusätzliche AbuseIPDB-Prüfung erforderlich ist.
9. **DNS/PTR-Prüfung:** Bei Cache-Miss wird die Quelladresse asynchron aufgelöst und bewertet.
10. **AbuseIPDB:** Nur wenn die DNS-Stufe ACCEPT mit dem neutralen Grund `-` ergibt und der Zielport in `ABUSEIPDB_PORTS` konfiguriert ist, folgt die API-Prüfung.
11. **Endgültiges Verdict:** Erst nach Abschluss der erforderlichen Stufen wird das Paket angenommen oder verworfen und die endgültige Entscheidung – soweit zulässig – im Hauptcache gespeichert.

Die Reihenfolge ist relevant: Eine statische Whitelist steht vor allen dynamischen Prüfungen. Eine dynamische Helper-Freigabe kann dagegen eine bereits vorhandene allgemeine DROP-Entscheidung nicht aufheben.

## 4. DNS- und PTR-Prüfung

### 4.1 Resolver und Abfrage

Für eine Quell-IP wird eine Reverse-DNS-Abfrage (PTR) durchgeführt. Die Resolver und Zeitlimits werden in `config.py` festgelegt. Die Implementierung verwendet DNS direkt über UDP und benötigt dafür kein zusätzliches Python-Paket.

Mehrere DNS-Worker bearbeiten Anfragen parallel. Die Resolver werden rotierend verwendet; Resolver mit kürzlich aufgetretenen Fehlern werden bei der Reihenfolge nach hinten gestellt. Wartende Anfragen derselben Cache-Adresse werden gebündelt.

### 4.2 PTR-Blockliste

Die Datei `blocked_ptr.txt` enthält Domainmuster, die zu DROP führen. Groß-/Kleinschreibung wird ignoriert. Ein Eintrag wird als Domain-Suffix mit einer Begrenzung an der Domain-Grenze behandelt. Das Zeichen `*` steht für einen variablen Teil der Domain.

Ein Treffer wird als DNS-Blockentscheidung mit Grund `B` gespeichert. Die gefundene PTR-Domain und das passende Blocklistenmuster erscheinen im Log.

### 4.3 Ergebnis ohne PTR

Die Implementierung unterscheidet nach Adressfamilie:

- **IPv4 ohne PTR:** DROP mit temporärer Sperrzeit.
- **IPv6 ohne PTR:** ACCEPT mit temporärer Cache-Zeit.

Ein fehlender PTR ist damit nicht für beide Adressfamilien gleich zu bewerten.

### 4.4 DNS-Fehler und Gesundheitstest

Wenn die PTR-Abfragen fehlschlagen, führt NFQfilter einen gemeinsamen Gesundheitstest aus. Dabei wird die konfigurierte Test-IP aufgelöst und das erwartete PTR-Ergebnis geprüft.

- **Gesundheitstest erfolgreich:** Die Resolver gelten als grundsätzlich erreichbar. Der vollständige PTR-Fehler führt zu DROP mit dem konfigurierten längeren TTL.
- **Gesundheitstest fehlgeschlagen:** Die DNS-Stufe wird neutral behandelt und führt temporär zu ACCEPT. Andere Filterstufen, die bereits vorher geprüft wurden, bleiben davon unberührt.

Ein interner Fehler im DNS-Worker wird im Fehlerpfad als temporäre DROP-Entscheidung behandelt. DNS-Zwischenergebnisse und endgültige Paketentscheidungen werden getrennt verwaltet.

## 5. AbuseIPDB

NFQfilter unterstützt die AbuseIPDB-API v2 über den Endpunkt `/api/v2/check`.

Die Abfrage erfolgt nur, wenn alle folgenden Bedingungen erfüllt sind:

- AbuseIPDB ist aktiviert.
- Der Zielport ist in `ABUSEIPDB_PORTS` enthalten.
- Die DNS/PTR-Prüfung hat ACCEPT mit dem neutralen Grund `-` ergeben.
- Es liegt ein Cache-Miss für die API-Bewertung vor.

Der API-Key wird als HTTP-Header übertragen. Die Verbindung verwendet HTTPS mit Zertifikatsprüfung. Die Abfrage enthält die Quell-IP und den konfigurierten Zeitraum `ABUSEIPDB_MAX_AGE_DAYS`.

### 5.1 Portabhängige Bewertung

`ABUSEIPDB_PORTS` ist ein Mapping aus TCP-Port und Mindestscore. Ein Score größer oder gleich dem Grenzwert des angesprochenen Ports führt zu DROP.

Beispiel für das Konfigurationsformat:

```python
ABUSEIPDB_PORTS = {
    443: 40,
    5001: 60,
}
```

Der API-Cache speichert den unveränderten Score. Die Entscheidung wird bei jeder Verbindung anhand des jeweiligen Zielports neu berechnet. Ein DROP auf einem Port führt deshalb nicht automatisch zu DROP auf einem anderen Port.

Eine einzelne API-Abfrage kann für mehrere wartende Verbindungen und mehrere konfigurierte Ports wiederverwendet werden. Bei zeitgleichen Anfragen wird nur der erste Vorgang als neue API-Abfrage protokolliert; nachfolgende Vorgänge verwenden den Cache.

### 5.2 Fehler und Rate-Limit

Bei API-Fehlern oder Timeouts wird keine positive Abuse-Bewertung erfunden. Stattdessen wird für die konfigurierte Fehler-TTL eine temporäre ACCEPT-Entscheidung mit Fehlergrund `E` gespeichert.

Bei HTTP 429 wird zusätzlich eine globale API-Pause anhand des `Retry-After`-Headers berücksichtigt. Ist die API-Warteschlange voll, werden wartende Pakete nicht unbegrenzt gehalten; der Fehlerpfad verwendet ebenfalls eine zeitlich begrenzte Fehlerentscheidung.

Ein AbuseIPDB-DROP ist portabhängig und wird deshalb nicht als allgemeine, portübergreifende DROP-Entscheidung im Hauptcache gespeichert. Der Rohscore bleibt im separaten API-Cache verfügbar.

## 6. IPv4- und IPv6-Verhalten

NFQfilter verwendet je nach Funktion unterschiedliche Cache- und Sperrgranularitäten:

| Funktion | IPv4 | IPv6 |
|---|---|---|
| DNS-, API- und allgemeiner Entscheidungs-Cache | einzelne IP (/32) | Präfix (/64) |
| Einzel-IP-SYN-Erkennung | einzelne IP (/32) | einzelne IP (/128) |
| dynamische Einzel-IP-Sperre | /32 | /128 |
| netzbasierte /24-Erkennung | /24 | nicht verwendet |
| Kernel-Fastdrop für Einzel-IP-Sperren | /32 | /128 |

### 6.1 IPv6-/64-Cache

Für DNS-, AbuseIPDB- und endgültige Entscheidungs-Caches wird eine IPv6-Adresse auf ihr /64-Präfix normalisiert. Eine Bewertung kann damit für andere Adressen desselben /64 wiederverwendet werden.

Die Einzel-IP-Erkennung bleibt davon getrennt: Sie arbeitet weiterhin auf der konkreten IPv6-Adresse (/128). Eine auffällige Adresse führt daher nicht automatisch zur dynamischen Sperre des gesamten /64.

### 6.2 IPv6-Zielerkennung in der Firewall

Das konfigurierte IPv6-Ziel kann mit einer nicht zusammenhängenden Maske angegeben werden. Damit kann eine feste Host-ID unabhängig von einem wechselnden globalen /64-Präfix erkannt werden. Das ist eine Zieladress-Maske und keine /64-Quellnetzregel.

## 7. SYN-Erkennung und dynamische Einzel-IP-Sperren

Die Einzel-IP-Erkennung beobachtet ausschließlich TCP-SYN-Pakete auf den in `SINGLE_IP_PORTS` konfigurierten Zielports.

Sie besitzt drei Erkennungsschwellen:

- mindestens 10 SYN innerhalb von 60 Sekunden an denselben Zielport,
- mindestens 20 SYN innerhalb von 300 Sekunden an denselben Zielport,
- mindestens 5 SYN mit identischem Quellport und Zielport innerhalb von 20 Minuten, wobei zwischen dem ersten und letzten SYN mindestens 60 Sekunden liegen.

Die Bewertung erfolgt erst, nachdem die normale Filterentscheidung bekannt ist.

### 7.1 Verhalten abhängig von der bisherigen Entscheidung

- **Statische Whitelist:** Nur Hochlaststatistik. Keine Scrambler-Prüfung und keine dynamische Einzel-IP-Sperre.
- **Bereits abgewiesene Quelle:** Wird eine Erkennungsschwelle erreicht, erfolgt unmittelbar eine Einzel-IP-Sperre. Der Scrambler wird nicht befragt.
- **Akzeptierte Quelle:** Bei Erreichen einer Schwelle wird der konfigurierte Helper-Dienst asynchron befragt.

### 7.2 Helper-/Scrambler-Ergebnis

Der Helper wird per TCP angesprochen. NFQfilter sendet die IP-Adresse als ASCII-Text und erwartet eine der Antworten:

- `ACCESS`: Quelle wird für eine Stunde dynamisch freigegeben (WHITE).
- `BAD`: unmittelbare Einzel-IP-Sperre (BLOCK).
- `UNKNOWN`: Quelle wird für eine Stunde in BLACK gesetzt. Bei einem weiteren vollständigen Regelverstoß kann daraus eine Einzel-IP-Sperre entstehen.
- Verbindungs-, Protokoll- oder Warteschlangenfehler: eigener ERROR-Zustand für fünf Minuten. Ein technischer Fehler wird ausdrücklich nicht als UNKNOWN interpretiert.

Die dynamischen Einzel-IP-Sperren gelten für eine Stunde ab dem letzten erkannten Treffer. Weitere Treffer können die Sperrzeit verlängern.

### 7.3 Hochlastmeldung

Unabhängig von den eigentlichen Sperrschwellen gibt es eine reine Beobachtungsgrenze:

- 60 SYN in 10 Minuten oder
- 120 SYN in einer Stunde

lösen eine HIGHLOAD-Meldung aus. Pro IP wird diese Meldung höchstens einmal pro Stunde geschrieben. Die Hochlastmeldung allein löst keine automatische Sperre aus.

## 8. Netzbasierte Angriffserkennung

### 8.1 IPv4-/24-Erkennung

Auf den konfigurierten `SUBNET24_PORTS` beobachtet NFQfilter unterschiedliche IPv4-Quelladressen innerhalb desselben /24-Netzes.

Werden innerhalb des konfigurierten Zeitfensters mindestens `SUBNET24_THRESHOLD` unterschiedliche Quell-IP-Adressen erkannt, wird das betreffende /24-Netz zeitlich begrenzt gesperrt.

Wiederholte Pakete derselben Quell-IP erhöhen den Zähler der unterschiedlichen Quellen nicht. IPv6 wird von dieser /24-Erkennung nicht erfasst.

### 8.2 Einzel-IP-SYN-Flutschutz

Davon unabhängig gibt es einen separaten SYN-Flutschutz pro Quell-IP und Zielport. Er zählt unterschiedliche TCP-Quellports innerhalb des konfigurierten Zeitfensters. Ein wiederholtes SYN mit demselben Quellport wird im Fenster nur einmal gezählt.

Wird die portbezogene Schwelle erreicht und liegt zwischen erstem und letztem Ereignis die konfigurierte Mindestdauer, wird die Quell-IP zeitlich begrenzt gesperrt. In der mitgelieferten Konfigurationsstruktur sind unterschiedliche Grenzwerte pro Zielport vorgesehen.

## 9. Datenhaltung und Cache-Persistenz

Der laufende Filter hält seine Entscheidungs- und Zustandsdaten im Arbeitsspeicher. Der `StateWorker` sichert diese Daten regelmäßig und nach relevanten Zustandsänderungen in `cache_state.json`.

Gespeichert werden unter anderem:

- allgemeine endgültige Entscheidungen,
- DNS-Zwischenergebnisse,
- AbuseIPDB-Scores und API-Fehlerzustände,
- das Ende einer globalen AbuseIPDB-Pause,
- dynamische Helper-Freigaben und -Sperren,
- IPv4-/24-Zustände,
- Einzel-IP-SYN- und Sperrzustände,
- Zustände des Einzel-IP-Floodschutzes.

Die Sicherung erfolgt standardmäßig im 60-Sekunden-Intervall. Ereignisse können eine zusätzliche Sicherung anfordern; ein Debounce begrenzt dabei unnötige Schreibvorgänge.

Die Datei wird zunächst als temporäre Datei geschrieben, per `fsync` synchronisiert und anschließend atomar mit `os.replace` ersetzt. Soweit das Dateisystem es unterstützt, wird auch das Verzeichnis synchronisiert.

Ablaufzeiten werden als absolute Zeitpunkte gespeichert. Ein Neustart setzt eine noch gültige Sperre daher nicht pauschal auf ihre volle ursprüngliche Dauer zurück. Abgelaufene Einträge werden beim Wiederherstellen verworfen.

Das Cache-Dateiformat hat Version 2. Version-1-Zustände können eingelesen und auf die aktuelle Cache-Granularität überführt werden. Bei zusammenfallenden alten IPv6-Einträgen hat eine noch gültige DROP-Entscheidung Vorrang.

## 10. Konfiguration und Verzeichnisstruktur

Programmdateien und persistente Daten sind getrennt. Das zentrale Datenverzeichnis wird am Anfang von `nfqfilter.py` über `DATA_DIR` festgelegt.

Beispiel für die vorgesehene Installation:

```text
/persistent/
├── nfqfilter_13.6/
│   ├── nfqfilter.py
│   ├── abuseipdb_worker.py
│   ├── cache.py
│   ├── dns_worker.py
│   ├── firewall_rules.py
│   ├── helper_client.py
│   ├── ...
│   └── weitere Python-Module
│
└── nfqfilter.data/
    ├── config.py
    ├── blocked_ptr.txt
    ├── whitelist_ipv4.txt
    ├── whitelist_ipv6.txt
    ├── cache_state.json
    ├── tc_subnet24_state.json
    ├── dns_errors.log
    └── logs/
        ├── nfqfilter.log
        └── nfqfilter_whitelist.log
```

In der ausgelieferten Programmdatei ist `DATA_DIR` als absoluter Pfad vorgesehen. Wird der Wert auf einen leeren String gesetzt, verwendet NFQfilter stattdessen das Unterverzeichnis `data` neben `nfqfilter.py`.

Die Konfiguration muss direkt im gewählten Datenverzeichnis als `config.py` liegen. Fehlt sie oder kann sie nicht geladen werden, bricht der Programmstart vor dem Öffnen der NFQUEUE ab.

Die Konfiguration wird einmal zentral geladen und unter dem Modulnamen `config` registriert. Alle Projektmodule verwenden dasselbe Konfigurationsmodul. Änderungen an der Konfiguration werden erst nach einem Neustart wirksam.

### 10.1 Wichtige Konfigurationsgruppen

| Bereich | Zentrale Parameter |
|---|---|
| Firewall | `NFQ_PORTS`, `NFQ_INTERFACE`, `NFQ_IPV4_TARGET`, `NFQ_IPV6_TARGET`, `NFQ_EXCLUDE_IPV4`, `NFQ_EXCLUDE_IPV6` |
| DNS | `DNS_SERVERS`, `DNS_TIMEOUT`, `DNS_WORKERS`, `CACHE_TTL` |
| AbuseIPDB | `ABUSEIPDB_ENABLE`, `ABUSEIPDB_API_KEY`, `ABUSEIPDB_PORTS`, `ABUSEIPDB_TIMEOUT`, `ABUSEIPDB_MAX_AGE_DAYS` |
| Helper | `HELPER_HOST`, `HELPER_PORT`, `CONNECT_TIMEOUT`, `READ_TIMEOUT` |
| IPv4-/24 | `SUBNET24_PORTS`, `SUBNET24_THRESHOLD`, `SUBNET24_WINDOW`, `SUBNET24_BLOCK_TTL` |
| Einzel-IP-Flood | `IP_FLOOD_PORTS`, `IP_FLOOD_WINDOW`, `IP_FLOOD_MIN_DURATION`, `IP_FLOOD_BLOCK_TTL` |
| Einzel-IP-SYN | `SINGLE_IP_PORTS`, `SINGLE_FAST_60`, `SINGLE_FAST_300`, `SINGLE_REPEAT_COUNT`, `SINGLE_REPEAT_WINDOW` |
| Persistenz | `STATE_FILE`, `STATE_SAVE_INTERVAL`, `STATE_SAVE_DEBOUNCE` |
| Logging | `DEBUG`, `LOG_DIR`, `LOG_FILE`, `LOG_WHITELIST_FILE` |
| optionale Kernel-Funktionen | `IP32_KERNEL_ENABLE`, `TC24_ENABLE` |

### 10.2 Listen und Dateien

- `blocked_ptr.txt`: PTR-Domainmuster, die zu DROP führen.
- `whitelist_ipv4.txt`: statische IPv4-Adressen und Netze.
- `whitelist_ipv6.txt`: statische IPv6-Adressen und Netze.
- `cache_state.json`: gesicherter Laufzeitzustand.
- `tc_subnet24_state.json`: Zustand der optionalen tc-/24-Funktion.
- `dns_errors.log`: DNS-Fehlerdiagnose.
- `logs/nfqfilter.log`: normale Entscheidungen und Ereignisse.
- `logs/nfqfilter_whitelist.log`: ausschließlich ACCEPT-Entscheidungen der statischen Whitelist.

Nicht jede Datei muss bereits bei einer frischen Installation vorhanden sein. Laufzeitdateien werden je nach Funktion angelegt.

### 10.3 Datenverzeichnis und Zugangsdaten

Die individuelle `config.py` enthält unter anderem den AbuseIPDB-Key und lokale Netz-/Dienstparameter. Sie gehört in das persistente Datenverzeichnis und sollte nicht unkontrolliert veröffentlicht oder durch eine Beispielkonfiguration ersetzt werden.

Der API-Key darf nicht in Logs, Screenshots oder öffentlichen Commits erscheinen. Für ein öffentliches Repository ist eine bereinigte Beispielkonfiguration ohne persönliche Zugangsdaten und lokale Betriebswerte zu verwenden.

## 11. Protokollierung

Die Protokollierung erfolgt tabulatorgetrennt. Die Felder enthalten:

1. Zeitstempel,
2. Entscheidung und Entscheidungsgrund,
3. Zielport,
4. Quell-IP,
5. TCP-Quellport,
6. TCP-Flags,
7. verwendeten DNS-Resolver,
8. PTR-/Trefferinformation, Detailtext oder AbuseIPDB-Score.

Wichtige Entscheidungsgründe sind unter anderem:

| Kennung | Bedeutung |
|---|---|
| `W` | statische Whitelist |
| `H` | dynamische Helper-Liste |
| `B` | PTR-Blockliste |
| `T` | DNS-Fehler-/Timeoutpfad |
| `A` | AbuseIPDB-Bewertung |
| `E` | temporärer Fehlerzustand |
| `C` | Cache-Treffer |
| `F` | Einzel-IP-SYN-Flutschutz |
| `I` | Einzel-IP-Erkennung oder -Sperre |
| `/24` | IPv4-/24-Erkennung |

Die interne AbuseIPDB-Kennung `A` wird nicht als sichtbarer Loggrund ausgegeben. Stattdessen wird der Score in einem eigenen Feld kompakt dargestellt. Bei einem Cache-Treffer wird kein neuer PTR- oder Score-Eintrag wiederholt.

Nur `ACPT W` wird in die separate Whitelist-Logdatei geschrieben. Alle anderen Entscheidungen gehen in die normale Logdatei. Werden beide Logpfade identisch konfiguriert, wird eine Zeile trotzdem nur einmal geschrieben.

Die Protokollierung wird über `DEBUG` gesteuert. Bei deaktiviertem DEBUG werden keine Entscheidungszeilen geschrieben.

## 12. Start, Stop und Fehlerverhalten

### 12.1 Startreihenfolge

Der Programmstart erfolgt in dieser Reihenfolge:

1. Konfiguration aus `DATA_DIR/config.py` laden.
2. Exklusive Instanzsperre über `.nfqfilter.lock` erwerben.
3. Gesicherten Laufzeitzustand wiederherstellen.
4. StateWorker starten.
5. NFQUEUE-Bibliothek öffnen und IPv4/IPv6 an die Queue anbinden.
6. NFQUEUE 0 erzeugen und den vollständigen Paketinhalt anfordern.
7. Erst nachdem der Userspace-Listener bereit ist, die eigenen Firewallregeln installieren.
8. Optionale tc- und Kernel-IP32-Worker starten, sofern aktiviert.
9. Pakete aus dem NFQUEUE-Dateideskriptor lesen und verarbeiten.

Die Reihenfolge stellt sicher, dass die Firewallregeln nicht vor dem Userspace-Listener aktiv werden.

### 12.2 Kontrollierter Stop

Bei SIGINT oder SIGTERM wird der Prozess kontrolliert beendet. Dabei werden:

1. die eigenen NFQfilter-Regeln entfernt,
2. optionale Kernel-Worker beendet,
3. der persistente Zustand abschließend gespeichert,
4. die NFQUEUE geschlossen,
5. die Netfilter-Queue und der Handle freigegeben.

Die Instanzsperre verhindert, dass zwei NFQfilter-Prozesse gleichzeitig dieselben Queue- und Firewallregeln verwalten.

### 12.3 Unkontrollierter Abbruch

Bei SIGKILL, Kernelabsturz oder Stromausfall kann Python keine Cleanup-Routine ausführen. Eigene Firewallregeln können deshalb zunächst bestehen bleiben. Beim nächsten regulären Start werden die eindeutig als NFQfilter-Regeln markierten Einträge bereinigt und neu erstellt.

Eine Firewall-Neuprovisionierung durch UniFi während des laufenden Prozesses kann manuell verwaltete POSTROUTING-Regeln entfernen. Version 13.6 enthält keinen allgemeinen Watcher, der diese direkten NFQUEUE-Regeln nach jeder Provisionierung automatisch wiederherstellt.

## 13. Optionale Kernel-Funktionen

Zwei zusätzliche Funktionen sind im Quellcode enthalten, aber in der mitgelieferten Konfiguration standardmäßig deaktiviert.

### 13.1 Einzel-IP-Kernel-Fastdrop

`IP32_KERNEL_ENABLE = False` ist der Standard.

Bei Aktivierung verwaltet der Worker dedizierte IPv4-/IPv6-ipsets mit Paket-Zählern und Regeln in mangle/PREROUTING. Er synchronisiert dort bereits im Userspace erkannte Einzel-IP-Sperren. Die Sperrgranularität bleibt IPv4 /32 und IPv6 /128.

Der Worker prüft die eigenen Regeln regelmäßig und kann sie nach einem Verlust wiederherstellen. Kernel-Zähler werden vor Ablauf einer Sperre ausgewertet, damit erneute Treffer die Sperrzeit verlängern können. Ist die Kernel-Funktion nicht verfügbar, bleibt die DROP-Entscheidung im NFQUEUE-Callback bestehen.

### 13.2 tc-basierter IPv4-/24-Fastdrop

`TC24_ENABLE = False` ist ebenfalls der Standard.

Bei Aktivierung kann der tc-Worker bereits erkannte IPv4-/24-Sperren als Ingress-Filter auf dem konfigurierten Interface umsetzen. Er verwaltet dafür eigene Prioritäten, gleicht Sperrlisten ab und liest Paket-Zähler aus. Die tc-Regeln dienen der Entlastung bei bereits erkannten Sperren; die Erkennung selbst erfolgt weiterhin durch den Userspace-Tracker.

Die Funktion benötigt passende tc-Unterstützung und eine korrekte Interface-Konfiguration. Sie sollte erst nach gesonderter Prüfung auf dem Zielrouter aktiviert werden.

## 14. Installation und Versionswechsel

Die folgenden Punkte beschreiben das Installationsprinzip der Version 13.6. Sie ersetzen keine Prüfung der konkreten Routerumgebung.

1. Vorhandenes Programm- und Datenverzeichnis vollständig sichern.
2. NFQfilter kontrolliert beenden.
3. Programmdateien in das Versionsverzeichnis übernehmen.
4. Das persistente Datenverzeichnis erhalten. Insbesondere die individuelle `config.py`, Whitelists, `blocked_ptr.txt`, Cache- und Statusdateien sowie Logs nicht durch Archiv-Beispieldateien überschreiben.
5. Prüfen, dass `DATA_DIR` in `nfqfilter.py` auf das gewünschte Datenverzeichnis zeigt.
6. Prüfen, dass die Bibliothek `libnetfilter_queue.so.1` sowie die benötigten Netfilter-Werkzeuge auf dem Gateway vorhanden sind.
7. NFQfilter mit den erforderlichen Root-Rechten und über den vorhandenen Autostart starten.
8. Startmeldungen, eigene Firewallregeln und die Logdateien kontrollieren.

Bei einem Versionswechsel werden grundsätzlich die Programmdateien aktualisiert. Das externe Datenverzeichnis bleibt bestehen. Konfigurationsänderungen zwischen Versionen müssen gezielt in die vorhandene individuelle `config.py` übernommen werden; die Beispielkonfiguration darf nicht blind darüberkopiert werden.

Der Quellcode installiert keinen eigenständigen systemd-Dienst und richtet keinen gerätespezifischen Boot-Mechanismus ein. Der vorhandene Startmechanismus muss NFQfilter nach der Initialisierung der UniFi-Firewall starten.

## 15. Grenzen und Sicherheitsaspekte

- NFQfilter ist ein Zusatzfilter und kein Ersatz für die Gateway-Firewall.
- Die dokumentierten Zielgeräte sind UCG-Ultra und UXG-Lite. Andere Geräte und Softwarestände sind nicht automatisch kompatibel.
- Die direkte Firewall-Anbindung setzt voraus, dass die verwendeten iptables-/ip6tables-Erweiterungen, conntrack und NFQUEUE verfügbar sind.
- Die Queue-Regeln erfassen nur den konfigurierten TCP-SYN-Verkehr. Andere Protokolle und Pakete werden nicht durch die beschriebene Entscheidungslogik geprüft.
- Der Paketparser erwartet bei IPv6 TCP unmittelbar nach dem festen IPv6-Header. Eine allgemeine Verarbeitung beliebiger IPv6-Extension-Header ist nicht implementiert.
- DNS- und AbuseIPDB-Entscheidungen hängen von externen Diensten und deren Erreichbarkeit ab. Die jeweiligen Fehlerpfade sind zeitlich begrenzt und ausdrücklich von regulären negativen Bewertungen getrennt.
- Bei Queue-Bypass kann der Verkehr ohne zusätzlichen NFQfilter-Schutz passieren, wenn kein Listener vorhanden ist.
- Bei unkontrolliertem Prozessabbruch kann Cleanup ausbleiben, bis der nächste reguläre Start erfolgt.
- Die optionalen Kernel-Fastdrop-Funktionen sind standardmäßig ausgeschaltet. Ihre Aktivierung benötigt eine gesonderte Prüfung von Interface, Kernelmodulen, ipset und tc.
- Die mitgelieferte Konfiguration ist eine Vorlage und muss an das konkrete Gateway und Zielsystem angepasst werden.
- Die Quellcode-Syntaxprüfung allein ersetzt keinen Live-Test auf dem Zielrouter.

## 16. Aufbau des Quellcodes

| Datei | Aufgabe |
|---|---|
| `nfqfilter.py` | Einstiegspunkt, Konfigurationsladen, NFQUEUE-Callback, zentrale Entscheidungsreihenfolge und Prozesssteuerung |
| `firewall_rules.py` | Installation und Entfernung der eigenen IPv4-/IPv6-NFQUEUE-Regeln |
| `packet.py` | Dekodierung der IPv4-/IPv6- und TCP-Header |
| `dns_worker.py` | PTR-Auflösung, Resolververwaltung, Gesundheitstest und DNS-Entscheidungscache |
| `ptr_blocklist.py` | Laden und Auswerten der PTR-Blockliste |
| `abuseipdb_worker.py` | AbuseIPDB-API v2, Worker-Queue, Score-Cache und portbezogene Bewertung |
| `helper_client.py` | TCP-Kommunikation mit dem externen Helper-/Scrambler-Dienst |
| `single_ip_filter.py` | SYN-Erkennung, Scrambler-Zustände, Hochlastmeldung und dynamische Einzel-IP-Sperren |
| `ip_flood.py` | Erkennung vieler unterschiedlicher SYN-Quellports einer einzelnen IP |
| `cache.py` | RAM-Caches, TTL-Sets und IPv6-/64-Cache-Schlüssel |
| `state_worker.py` | Wiederherstellung und persistente Sicherung des Laufzeitzustands |
| `whitelist.py` | Laden und Prüfen statischer IPv4-/IPv6-Whitelists |
| `logger.py` | Tabulatorgetrennte Protokollierung und Trennung der Whitelist-Logs |
| `kernel_ip32.py` | Optionale Kernel-Sperren für einzelne IPv4-/IPv6-Adressen |
| `tc_subnet24.py` | Optionale tc-Ingress-Sperren für erkannte IPv4-/24-Netze |
| `filter.py` | Zusätzliche dateibasierte IPv4-/IPv6-Netzprüfung; nicht Teil des zentralen NFQUEUE-Callbacks in `nfqfilter.py` |
| `config.py` | Kompatibilitätsmodul für Offline-Tests; der Laufzeitprozess lädt die Konfiguration aus dem Datenverzeichnis |

---

## Projektlizenz

NFQfilter wird unter den projektspezifischen Nutzungsbedingungen aus [LICENSE](LICENSE) bereitgestellt. Die Lizenz erlaubt private, nicht kommerzielle Nutzung und private Änderungen. Weitergabe, Veröffentlichung veränderter Fassungen und kommerzielle Nutzung sind ohne vorherige schriftliche Zustimmung nicht gestattet. Maßgeblich ist der vollständige Wortlaut der Lizenzdatei.
