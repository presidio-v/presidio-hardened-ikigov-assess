# presidio-hardened-ikigov-assess

[🇬🇧 English](https://github.com/presidio-v/presidio-hardened-ikigov-assess/blob/main/README.md) · 🇩🇪 **Deutsch**

[![PyPI version](https://img.shields.io/pypi/v/presidio-hardened-ikigov-assess.svg)](https://pypi.org/project/presidio-hardened-ikigov-assess/)
[![Python](https://img.shields.io/pypi/pyversions/presidio-hardened-ikigov-assess.svg)](https://pypi.org/project/presidio-hardened-ikigov-assess/)
[![GitHub release](https://img.shields.io/github/v/release/presidio-v/presidio-hardened-ikigov-assess.svg)](https://github.com/presidio-v/presidio-hardened-ikigov-assess/releases)
[![Tests](https://github.com/presidio-v/presidio-hardened-ikigov-assess/actions/workflows/pytest.yml/badge.svg)](https://github.com/presidio-v/presidio-hardened-ikigov-assess/actions/workflows/pytest.yml)
[![CodeQL](https://github.com/presidio-v/presidio-hardened-ikigov-assess/actions/workflows/codeql.yml/badge.svg)](https://github.com/presidio-v/presidio-hardened-ikigov-assess/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/presidio-v/presidio-hardened-ikigov-assess/badge)](https://scorecard.dev/viewer/?uri=github.com/presidio-v/presidio-hardened-ikigov-assess)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13748/badge)](https://www.bestpractices.dev/projects/13748)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**IKI-Gov Assessment Tool** — überführt das IKI-Gov-Referenzmodell (Integrated KI-Governance Reference Model) in ein praxistaugliches CLI-Werkzeug, das KI-Anwendungsfälle gegen ein strukturiertes Governance-Rahmenwerk bewertet.

Das IKI-Gov-Rahmenwerk ordnet KI-Governance entlang eines zentralen Lebenszyklus
(Kontext → Konzeption → Entwicklung → Freigabe → Betrieb → Anpassung → Außerbetriebnahme),
umgeben von sechs Domänen und gemessen über sechs Dimensionen (M1–M6) mit sechs Qualitäts-Gates
(G0–G5).

Referenz: Stantchev, V. *IKI-Gov-Referenzmodell* (Integrated KI-Governance Reference Model).

---

## Das Buch

Dieses Werkzeug implementiert das **IKI-Gov-Referenzmodell**, vorgestellt in der
Springer-Monografie von Vladimir Stantchev, die in zwei Ausgaben erscheint:

- **AI and IT Governance** (Englisch) — Springer, Berlin; ISBN 978-3-662-74001-9; erscheint am 11. Januar 2027
- **KI und IT-Governance** (Deutsch) — Springer, Berlin; ISBN 978-3-662-74093-4; erscheint am 28. Dezember 2026

Das Buch führt von klassischer IT-Governance (COBIT, ITIL, ISO/IEC 38500) hin zu KI-Governance über
Ethik, Recht, Risiko und Daten und setzt daraus IKI-Gov zusammen: den Lebenszyklus, sechs Domänen,
sechs Messdimensionen (M1–M6) und sechs Qualitäts-Gates (G0–G5). Die 25 hier bewerteten
Checklisten-Punkte stammen aus dem Rahmenwerk-Kapitel des Buches und seinem Anhang zu Workshops und
Freigabe-Gates; die Zuordnungen zu ISO/IEC 42001 und EU AI Act folgen seinen Orientierungstabellen.

Das Buch versteht das Modell als begründete Synthese und als praxistaugliche Heuristik zur
Orientierung, nicht als Rechtsberatung und nicht als Konformitätsbewertung. Dieses Werkzeug hält
dieselbe Linie (siehe die Hinweise bei den Befehlen `euaiact-gap` und `iso-gap`). Beide Ausgaben
sind ab sofort bei Springer (Berlin) vorbestellbar; die Springer-Katalogseite und der DOI werden
hier ergänzt, sobald sie verfügbar sind.

---

## Installation

```bash
pip install presidio-hardened-ikigov-assess

# Mit CVE-Prüfung der Abhängigkeiten
pip install "presidio-hardened-ikigov-assess[audit]"

# Mit Ed25519-Public-Key-Nachweisprüfung
pip install "presidio-hardened-ikigov-assess[crypto]"
```

---

## Schnellstart

```bash
# Parametergesteuerte Bewertung
iga assess --use-case "fraud-scoring" --risk-class high --lang en \
    --affirm S1,S2,S3,D1,D2,T1,T4,O1,I1

# Interaktiver Assistent (Schritt für Schritt)
iga assess --interactive --lang de --risk-class high --use-case "kredit-scoring"

# Gate-Bereitschaftsprüfung
iga gate --gate G2 --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1,T4,O1,I1 --lang en

# Gate-Assertion für CI-Pipelines (Exit 0 OPEN / 2 PARTIAL / 3 BLOCKED)
iga gate --gate G1 --risk-class high --affirm S1,S2,D1,D2 --assert-gate G1

# Strikter Modus: übersprungene gate-kritische Punkte gelten als blockierend
iga gate --gate G2 --risk-class high --affirm S1,S2 --skip D3 --strict --assert-gate G2

# Maschinenlesbares JSON (skriptbar, ohne Fortschrittsbalken)
iga assess --affirm S1,S2,S3 --quiet
iga gate --gate G0 --affirm S1,S2 --skip S3 --quiet

# Bericht als Markdown ausgeben (stdout)
iga report --use-case "fraud-scoring" --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1 --format markdown

# Bericht als JSON ausgeben
iga report --use-case "fraud-scoring" --affirm S1,S2 --format json

# Bericht in eine Datei schreiben (Markdown oder JSON)
iga report --use-case "fraud-scoring" --affirm S1,S2,T4 --output audit/fraud-scoring.md
iga report --use-case "fraud-scoring" --affirm S1,S2 -f json -o fraud-scoring.json

# ISO/IEC-42001-Lückenanalyse auf Klausel-Ebene
iga iso-gap --use-case "fraud-scoring" --risk-class high --affirm S1,S2,S3,I1,I2
iga iso-gap --affirm S2,S3,I1,I2 --quiet   # maschinenlesbares JSON

# EU-AI-Act-Pflichten für Hochrisiko-Systeme (Art. 9–17), nur Hochrisiko-Systeme
iga euaiact-gap --use-case "fraud-scoring" --affirm S1,S2,S3,S4,S5,D1,D5
iga euaiact-gap --affirm S1,S2 --quiet

# Bewertungen persistieren und das Portfolio ansehen (SQLite unter ~/.iga/assessments.db)
iga assess --use-case "fraud-scoring" --risk-class high --affirm S1,S2,S3 --save
iga list                                   # Tabelle gespeicherter Bewertungen
iga portfolio                              # aggregierte M1–M6 + blockierte Gates
iga trend --use-case "fraud-scoring"       # Delta gegenüber dem vorherigen Lauf
iga delete --use-case "fraud-scoring"      # endgültig löschen

# Gespeicherte Bewertungen auflisten (Persistenz seit v0.6.0)
iga list
```

### Beispielausgabe

```
IKI-Gov Assessment — fraud-scoring  [risk: HIGH]

Measurement Dimensions
  M1  Strategie & Ownership          ████████░░   80.0 %
  M2  Data Quality & Lineage         ██████░░░░   60.0 %
  M3  Validation & Fairness          ████░░░░░░   40.0 %
  M4  Security & Robustness          █████████░   90.0 %
  M5  Compliance Evidence            ███░░░░░░░   30.0 %
  M6  Operations, Drift & Incidents  ██████░░░░   60.0 %
  ──────────────────────────────────────────────────────
       Overall maturity                           60.0 %

Gate Readiness
  G0  OPEN
  G1  OPEN
  G2  PARTIAL  [skipped: D3]
  G3  BLOCKED  — blocking: T5 (A security review of the model pipeline…)
  G4  BLOCKED
  G5  BLOCKED
```

> Die Beispielausgabe zeigt den `--lang en`-Lauf. Unter `--lang de` sind alle Laufzeitausgaben
> vollständig auf Deutsch.

---

## Checkliste

25 Punkte, abgeleitet aus den fünf Anhang-Abschnitten des IKI-Gov-Rahmenwerks:

| Präfix | Abschnitt | M-Dimension |
|--------|-----------|-------------|
| S1–S5 | Strategie & Geschäftsfall | M1 Strategie & Ownership |
| D1–D5 | Daten, Recht & Ethik | M2 Datenqualität & Lineage |
| T1–T3 | Modell, Sicherheit & Technik | M3 Validierung & Fairness |
| T4–T5 | Modell, Sicherheit & Technik | M4 Sicherheit & Robustheit |
| O1–O5 | Betrieb, Monitoring & Aufsicht | M6 Betrieb, Drift & Vorfälle |
| I1–I5 | ISO/IEC 42001 Abgleich | M5 Compliance-Nachweise |

---

## Scoring

```
score_m(dim) = sum(weight_i for affirmed items in dim)
               / sum(weight_i for non-skipped items in dim) × 100

overall = arithmetic mean(M1, M2, M3, M4, M5, M6)
```

Risikoklassen-Multiplikatoren: `low` = 1.0 · `medium` = 1.5 · `high` = 2.0.
Übersprungene Punkte werden aus Zähler und Nenner ausgeschlossen (konservativ).

---

## Gates

| Gate | Lebenszyklus-Übergang |
|------|-----------------------|
| G0 | Kontext → Konzeption |
| G1 | Konzeption → Entwicklung |
| G2 | Entwicklung → Freigabe |
| G3 | Freigabe → Betrieb |
| G4 | Betrieb → Anpassung |
| G5 | Anpassung → Außerbetriebnahme |

**Status:** **OPEN** (alle bestätigt) · **PARTIAL** (einige übersprungen, keine verneint) · **BLOCKED** (≥1 verneint)

### Risikoklassen-abhängige Schwellen (v0.3.0)

Wie Übersprünge behandelt werden, hängt von der aktiven Risikoklasse ab:

| Risikoklasse | Übersprungene gate-kritische Punkte |
|--------------|-------------------------------------|
| `low` | nachgesehen: ein Gate mit Übersprüngen, aber ohne Verneinungen ist **OPEN** |
| `medium` | toleriert: das Gate bleibt **PARTIAL**, bis sie bestätigt sind |
| `high` | nicht zulässig: Übersprünge **BLOCKIEREN** das Gate (standardmäßig strikt) |

`--strict` erzwingt das Hochrisiko-Verhalten in jeder Risikoklasse. Wenn ein Übersprung ein Gate
blockiert, wird dies separat ausgewiesen (`blocking_skips`), sodass der Grund für ein
BLOCKED-statt-PARTIAL-Gate explizit ist.

### CI-Exit-Codes

`--assert-gate Gn` beendet sich mit einem statusspezifischen Code, sodass Pipelines ohne Parsen der
Ausgabe verzweigen können:

| Exit-Code | Bedeutung |
|-----------|-----------|
| `0` | Gate OPEN |
| `2` | Gate PARTIAL |
| `3` | Gate BLOCKED |
| `1` | allgemeiner Fehler (ungültige Eingabe, Gate-Konflikt) |

`--quiet` (`-q`) bei `assess` und `gate` gibt ausschließlich maschinenlesbares JSON aus.

---

## Regulatorische Content Packs (v0.16.0)

Die Zuordnungen zu ISO/IEC 42001 und EU AI Act sind versionierte **Content Packs** hinter einer
generischen Abdeckungs-Engine, sodass neue Rahmenwerke als Daten hinzukommen:

```bash
iga content-list                              # eingebaute + externe Packs (Versionen, Hashes)
iga framework-gap --framework iso42001 --affirm S1,S2,D1
iga framework-gap --framework euaiact --risk-class high --affirm S1,S2,D5 --quiet
iga framework-gap --framework nist-ai-rmf --affirm S1,S2,S3   # NIST AI RMF (Govern/Map/Measure/Manage)
```

Ein Pack ordnet jedes Ziel (Klausel/Artikel) den Checklisten-Punkten oder Gates zu, die es belegen.
Legen Sie ein JSON-Pack in `IGA_CONTENT_PATH` (oder `~/.iga/content/`), um ein Rahmenwerk
hinzuzufügen oder zu überschreiben; ein externes Pack mit derselben `framework_id` überschreibt das
eingebaute. Die bisherigen Befehle `iso-gap` / `euaiact-gap` bleiben unverändert.

## ISO/IEC-42001-Abdeckung

`iga iso-gap` bildet die Bewertung auf die ISO/IEC-42001-Abdeckung auf Klausel-Ebene ab. Jede
Klauselgruppe (Klauseln 4–10 und Annex-A-Controls) wird als **covered** (alle zugeordneten
Checklisten-Punkte bestätigt), **partial** oder **gap** ausgewiesen, mit den offenen Punkten je
unvollständig abgedeckter Klausel:

```
ISO/IEC 42001 Coverage Gap Analysis — fraud-scoring  [risk: HIGH]

  4   Context of the organization      PARTIAL    (1/2)  — Outstanding items: S4
  5   Leadership                       COVERED    (4/4)
  8   Operation                        GAP        (0/13) — Outstanding items: D1, D2, …
  A   Annex A (Controls)               GAP        (0/12) — Outstanding items: …
```

Übersprungene und verneinte Punkte zählen als *nicht bestätigt* (keine Abdeckungs-Gutschrift). Die
Punkt→Klausel-Matrix ist aus der IKI-Gov-Orientierungstabelle (`tab:framework-iso42001-matrix`)
abgeleitet und in `checklist.ISO_CLAUSES_BY_ITEM` zentralisiert. Nutzen Sie `--quiet` für
maschinenlesbares JSON.

---

## EU AI Act (Hochrisiko-Systeme)

`iga euaiact-gap` bildet die Gate-Bereitschaft auf die EU-AI-Act-Pflichten für Hochrisiko-Systeme ab
(Titel III Kap. 2, Artikel 9–17). Jeder Artikel wird als OPEN / PARTIAL / BLOCKED ausgewiesen,
abhängig von der Bereitschaft der Gates, die seinen Nachweis erzeugen:

```
EU AI Act High-Risk Compliance Gap — fraud-scoring  [risk: HIGH]

  Art. 9   Risk management system     G0, G1, G2, G4   PARTIAL  — G2 BLOCKED, G4 BLOCKED
  Art. 10  Data and data governance   G1               OPEN
  Art. 11  Technical documentation    G2, G3, G5       BLOCKED  — G2/G3/G5 BLOCKED
```

Die Gate→Artikel-Zuordnung ist wortgetreu aus dem IKI-Gov-Buch übernommen
(`tab:framework-euaiact-gates`) und liegt in `euaiact.EU_AI_ACT_ARTICLE_GATES`. Der Befehl gilt nur
für Hochrisiko-Systeme (er beendet sich mit einer Warnung bei niedrigem/mittlerem Risiko); `--quiet`
gibt JSON aus.

> Dieses Werkzeug stellt keine Rechtsberatung und keine Konformitätsbewertung dar.

---

## Persistenz & Portfolio

`iga assess --save` persistiert eine Bewertung in einer lokalen SQLite-Datenbank unter
`~/.iga/assessments.db` (überschreibbar mit der Umgebungsvariablen `IGA_DB_PATH`). Die
Portfolio-Befehle arbeiten dann über gespeicherte Anwendungsfälle hinweg:

| Befehl | Zweck |
|--------|-------|
| `iga list` | Tabelle aller gespeicherten Bewertungen (Anwendungsfall, Risiko, Gesamt, Zeitstempel) |
| `iga portfolio` | Mittelwert M1–M6 und Gesamtreife über die jeweils jüngste Bewertung je Anwendungsfall, plus Anzahl der Anwendungsfälle mit je BLOCKED-Gate |
| `iga trend --use-case X` | Delta je Dimension (▲/▼/=), Änderung der Gesamtreife und Gate-Übergänge zwischen zwei gespeicherten Läufen (jüngster vs. vorheriger, oder ein `--from`/`--to`-Fenster) |
| `iga delete --use-case X` | Alle gespeicherten Bewertungen eines Anwendungsfalls endgültig löschen |

`list` und `portfolio` unterstützen `--quiet` für JSON. Gespeichert wird nur, was Sie angeben (Name
des Anwendungsfalls, Risikoklasse, Sprache, Antworten/Scores/Gates); die Datenbankdatei wird mit
Berechtigung `0600` und das Verzeichnis `~/.iga` mit `0700` angelegt. `delete` ist eine endgültige
Löschung; es wird kein Soft-Delete-Protokoll aufbewahrt.

---

## Externe Nachweise

Bestätigungen können durch **signierte Nachweise** untermauert werden, die von benachbarten
`presidio-hardened-*`-Controls erzeugt werden (erster Producer: `presidio-hardened-ai`). Ein Punkt
wird damit von *selbst attestiert* zu *nachweisgestützt* aufgewertet, oder kryptografisch
**verifiziert** gegen einen lokalen Trust Store. Die Prüfung ist fail-closed: eine fehlende,
fehlerhafte oder falsche Signatur gilt nie als verifiziert.

```bash
# Punkte aus einem Nachweisdokument bestätigen, Signaturen gegen einen Trust Store prüfen
iga assess --use-case "fraud-scoring" --risk-class high \
    --evidence evidence.json --trust trust.json

# Fail-closed: nur Referenzen, die gegen --trust verifizieren, bestätigen ihren Punkt
iga assess --use-case "fraud-scoring" --risk-class high \
    --evidence evidence.json --trust trust.json --require-evidence

# Ein Dokument für sich prüfen (Exit 0 nur, wenn jede Referenz verifiziert)
iga verify-evidence --evidence evidence.json --trust trust.json
```

Ein **Nachweisdokument** ist das `EvidenceRef`-JSON des Producers:

```json
{
  "schema": "presidio-hardened/evidence-ref@1",
  "use_case": "fraud-scoring",
  "evidence": [
    {
      "item_id": "D1",
      "source": "presidio-hardened-ai",
      "source_version": "0.2.0",
      "ledger_ref": "pai-ledger:seq/0",
      "content_hash": "abc123def456",
      "signer": "presidio-hardened-ai",
      "signature": "2e7af6d2…",
      "claimed_at": "2026-06-08T00:00:00+00:00"
    }
  ]
}
```

Ein **Trust Store** ordnet jedem Signierer seinen Schlüssel zu. Ein Eintrag ist entweder ein
einfaches HMAC-Geheimnis (rückwärtskompatibel) oder ein Objekt, das Algorithmus und Schlüsselmaterial
angibt:

```json
{
  "presidio-hardened-ai": "shared-hmac-secret",
  "peer-control": { "alg": "ed25519", "public_key": "<64-hex-char public key>" }
}
```

Für **Schlüsselrotation** darf `public_key` (oder `key` bei HMAC) eine **Liste** sein: eine Signatur
verifiziert, wenn sie zu einem der gelisteten Schlüssel passt, sodass ein neuer Schlüssel während
eines Überlappungsfensters neben dem alten laufen kann; widerrufen wird durch Entfernen des
Schlüssels aus dem Store:

```json
{
  "peer-control": { "alg": "ed25519", "public_key": ["<new public key>", "<retiring key>"] }
}
```

Die Ed25519-Public-Key-Prüfung (RFC 8032) erlaubt es einem Prüfer, **nur öffentliche Schlüssel** zu
halten (kein geteiltes Geheimnis mit dem Producer) und erfordert das `[crypto]`-Extra. Signaturen
gehen über die kanonische Nachricht `{content_hash, signer}`; Signierer-Schlüssel werden
ausschließlich aus dem lokalen Trust Store aufgelöst (kein Netzwerk). Nachweisreferenzen tragen
Hashes und opake Ledger-URIs, niemals personenbezogene Daten.

> **Einordnung in die Suite:** ikigov-assess ist das Governance-*Rückgrat*, das Nachweise von
> benachbarten `presidio-hardened-*`-Controls konsumiert. Für die repoübergreifende Übersicht (wie
> die Familie ineinandergreift und eine End-to-End-Demo) siehe
> [presidio-hardened-* Suite Architecture](https://github.com/presidio-v/presidio-hardened-ai/blob/main/docs/ARCHITECTURE.md)
> (in `presidio-hardened-ai`).

---

## Gate-Zertifikate (v0.23.0)

Ein **Gate-Zertifikat** (`presidio-hardened/gate-certificate@1`) macht *das Zertifikat
zum Beweis*. Heute wird eine Gate-Entscheidung (`OPEN` / `PARTIAL` / `BLOCKED`) geglaubt,
weil `iga` sie berechnet hat. Ein Zertifikat kehrt das um: es ist ein kompaktes, signiertes
Artefakt, das jede dritte Partei **lokal** gegen einen Trust-Store prüft — **ohne
ikigov-assess auszuführen und ohne die Bewertungsdatenbank**. Das ist der Gegensatz zu
zentralen Policy-Decision-Points (Klasse Cedar / Zanzibar), bei denen das Urteil geglaubt
wird, weil ein Dienst es zurückgegeben hat. Es ist die Produktform des Programms der
Computational Jurisprudence (Stantchev, arXiv 2026): lokale Verifikation, keine Engine im
Vertrauenspfad, fail-closed.

Das Zertifikat trägt seine eigene Verankerung: das **hinreichende Bestätigungsset**
(pro Gate-Item `affirmed` / `skipped` / `denied`), etwaige **eingebettete Evidence-Refs**
wortgetreu und die **Prädikat-Eingaben der Entscheidung** — die Item-IDs des Gates, die
Risikoklasse, das effektive Strict-Flag und den Prädikat-Inhalts-Hash — sodass ein Prüfer
die Entscheidung allein aus dem Zertifikat nachrechnet und mit der Behauptung vergleicht.

```bash
# Signiertes Gate-Zertifikat nach der Gate-Auswertung ausstellen
iga certify --gate G2 --use-case "fraud-scoring" --risk-class high \
    --affirm S1,S2,D1,D2,D3,D4,D5,T1,T2,T3 \
    --evidence evidence.json --trust trust.json \
    --issuer "presidio-assessor" --sign-alg ed25519 \
    --sign-key-file issuer.key --output cert.json

# Lokal gegen einen Trust-Store prüfen — ohne DB, ohne Engine, fail-closed
iga verify-certificate --certificate cert.json --trust trust.json
```

Wenn `--evidence` an `iga certify` übergeben wird, ist `--trust` verpflichtend und jeder
Evidence-Ref muss vor dem Einbetten verifizieren; ein fehlschlagender Ref bricht die
Ausstellung ab. Die Verifikation führt danach unabhängig fünf Prüfungen mit je **eigenem
Fehlergrund** durch: unbekanntes Schema → `unknown-schema`; die Ausstellersignatur
(detached, über die kanonischen Bytes des Zertifikats **ohne das Feld `signature`**) →
`bad-signature` / `unknown-issuer`; Prädikat-Identität →
`predicate-content-mismatch`; jeder eingebettete Evidence-Ref gegen den Trust-Store des
Prüfers neu geprüft → `evidence-ref-failure`; und die aus den eingebetteten
Prädikat-Eingaben nachgerechnete Entscheidung gegen die Behauptung →
`decision-mismatch`. Gelesen werden nur Zertifikat und Trust-Store.

Kanonisierung und Signatur nutzen dieselben Familienkonventionen wie Evidence-Refs und das
Workshop-Manifest: kanonisches JSON `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` (UTF-8), SHA-256; die Ausstellersignatur ist HMAC-SHA256 oder Ed25519
(RFC 8032), aufgelöst über dieselbe Trust-Store-Form wie Evidence-Refs.

> **Umfang der Aussage (kein Overclaiming):** ein Gate-Zertifikat beweist, dass *unter dem
> deklarierten Prädikat und dem eingebetteten Bestätigungsset / den eingebetteten Nachweisen*
> die Gate-Entscheidung auf den behaupteten Wert nachrechnet. Es beweist **nicht**, dass die
> zugrunde liegenden Controls wirksam sind, noch dass die reale Aussage des Nachweises wahr
> ist. Assurance-Tiers (`assurance_tier`, evidence-ref@2 / presidio-evidence ADR-0003) sind
> ein **geplantes** Feld: die Evidence-Schicht dieses Repos (evidence-ref@1) modelliert noch
> keine Tiers, daher tragen Zertifikate keinen Tier.

---

## MCP-Server

Die Bewertungs-Engine steht auch als [Model-Context-Protocol](https://modelcontextprotocol.io)-Server
zur Verfügung, sodass MCP-fähige LLM-Agenten und -Clients IKI-Gov-Bewertungen als Werkzeuge ausführen
können.

```bash
# Installation mit dem MCP-Extra (erfordert Python 3.10+)
pip install "presidio-hardened-ikigov-assess[mcp]"

# Den Server über stdio starten
iga-mcp
```

Registrieren Sie ihn bei einem MCP-Client (z. B. Claude Desktop) über dessen Konfiguration:

```json
{
  "mcpServers": {
    "iki-gov-assess": {
      "command": "iga-mcp"
    }
  }
}
```

### Werkzeuge

| Werkzeug | Zweck |
|----------|-------|
| `iga_framework_info` | Beschreibt das Modell: Lebenszyklus-Phasen, Dimensionen M1–M6, Gates G0–G5, Abschnitte, Risikoklassen (de/en) |
| `iga_list_checklist` | Liefert alle 25 Checklisten-Punkte mit IDs, Text, Dimension, Gates und Abschnitt |
| `iga_assess` | Bewertet einen Anwendungsfall aus bestätigten/übersprungenen Punkt-IDs → M1–M6-Scores, Gesamtreife, Gate-Bereitschaft |
| `iga_assess_with_evidence` | Bewertet einen Anwendungsfall aus signierten `EvidenceRef`-Dokumenten und prüft Signaturen gegen einen Trust Store (HMAC oder Ed25519) |
| `iga_check_gate` | Bewertet die Bereitschaft eines einzelnen Gates G0–G5 mit blockierenden/übersprungenen Punkten |
| `iga_iso_gap` | Bildet bestätigte Punkte auf die ISO/IEC-42001-Klauselabdeckung ab (covered / partial / gap) |
| `iga_euaiact_gap` | Bildet auf EU-AI-Act-Hochrisikopflichten Art. 9–17 ab (OPEN / PARTIAL / BLOCKED) |

Alle Werkzeuge teilen sich die Eingabevalidierung und Ausgabe-Bereinigung der CLI, liefern dasselbe
strukturierte JSON-Schema wie `iga report --format json` und respektieren den Missbrauchsschutz je
Sitzung (sie geben einen Werkzeugfehler zurück, statt den Server bei Überschreitung zu beenden).

---

## Nachweispaket-Export (v0.15.0)

Exportieren Sie ein signiertes, auditfähiges Bündel einer Bewertung und prüfen Sie es später:

```bash
# Schreibt report.md + report.json + manifest.json (sha256 je Artefakt + Rahmenwerk-Hash).
# Versiegelt das Manifest mit einem HMAC-Schlüssel aus einer Datei (bleibt aus argv / Shell-Historie).
iga export --use-case fraud-scoring --risk-class high --affirm S1,S2,D1 \
    --bundle audit/fraud-scoring/ --sign-key-file ~/.iga/seal.key

# Artefakte erneut gegen das Manifest hashen (und die optionale HMAC-Versiegelung prüfen).
iga verify-bundle --bundle audit/fraud-scoring/ --sign-key-file ~/.iga/seal.key
```

Das `manifest.json` hasht jedes Artefakt inhaltlich und hält einen `framework_content_hash` fest, der
die Checkliste + ISO-/EU-AI-Act-Zuordnungen fixiert, die die Bewertung erzeugt haben, sodass jede
spätere Änderung von `verify-bundle` erkannt wird. Nutzen Sie `--zip`, um ein `.zip` zu erzeugen.
(PDF-Rendering und eine Public-Key-Signatur des Manifests sind zurückgestellt; das Hash-Manifest +
optionale HMAC-Versiegelung sind die Integritäts-Basislinie.)

Der Versiegelungsschlüssel wird aufgelöst aus `--sign-key-file <pfad>` (bevorzugt), dann
`--sign-key <key>` (inline; vermeiden, da in Shell-Historie und Prozessliste sichtbar), dann der
Umgebungsvariablen `$IGA_SIGN_KEY`. Nutzen Sie dieselbe Quelle für `export` und `verify-bundle`.

## Classificator-Bridge (eai-classification/v1)

> v0.20.0 — producer-agnostische Austauschschicht zwischen dem Enterprise AI Classification Framework
> und der IKI-Gov-Bewertungs-Engine.

Die Bridge akzeptiert Dokumente von **jedem Producer**, der dem Schema `eai-classification/v1`
entspricht: dem Forschungswerkzeug eai-classificator, partnerseitiger Erhebungssoftware oder
handgeschriebenem JSON. Das Schema ist am *Modell* ausgerichtet (6×6-Matrix: Typen T1–T6 ×
Autonomiestufen L1–L6), nicht am Ausgabeformat eines einzelnen Werkzeugs.

### Beispiel-Klassifikationsdokument

```json
{
  "schema": "eai-classification/v1",
  "producer": {"tool": "eai-classificator", "version": "1.0.0"},
  "use_cases": [
    {
      "id": "fraud-scoring",
      "type": "T1",
      "level": "L4",
      "name": {"de": "Betrugserkennung", "en": "Fraud Scoring"},
      "confidence": 0.92,
      "tags": ["finance", "high-risk"]
    },
    {
      "id": "customer-chat",
      "type": "T4",
      "level": "L3",
      "ecosystem": true
    }
  ]
}
```

**L6 / Ökosystem-Regime:** Stufe L6 ist die nicht-ordinale Ökosystem-/Mehrsystem-Koordinationsschicht.
Setzen Sie `"ecosystem": true` bei einem beliebigen L1–L5-Anwendungsfall, um anzuzeigen, dass er an
einem Mehrsystem-Koordinationsregime teilnimmt: der Parser normalisiert die effektive Zellstufe auf L6
und behält `base_level` im Datensatz. `level=L6` zusammen mit `ecosystem=false` ist ein Widerspruch
und wird abgelehnt.

### Ein Klassifikationsdokument einlesen

```bash
# Lesbare Tabelle: Anwendungsfall, Zelle, Risikovermutung, strict, Pflichten, Hinweis
iga classify ingest --file classification.json --lang de

# Maschinen-JSON: enthält Pack-content_hash und Producer-Echo
iga classify ingest --file classification.json --quiet
```

### Eine profilierte Bewertung aus einem Klassifikationsdokument ausführen

```bash
# Profil des gewählten Anwendungsfalls auflösen, dann die volle assess-Pipeline ausführen
iga classify assess \
    --file classification.json \
    --select fraud-scoring \
    --affirm S1,S2,D1,D2,T1 \
    --lang de \
    --quiet \
    --save

# risk_class und das strict-Flag des Profils sind aus dem Klassifikations-Pack vorbelegt.
# --strict kann weiter verschärfen; profilseitiges strict=true lässt sich nicht lockern.
```

Der Befehl `classify assess` nutzt die volle bestehende Pipeline wieder (`compute_scores`,
`evaluate_all_gates`, `render_json`, `store.save_assessment`, `log_security_event`) und protokolliert
ein Sicherheitsereignis `iga-classify-assess` inklusive Zell-ID und `content_hash` des Profil-Packs.

### Override des Klassifikationsprofil-Packs

Das eingebaute Pack (`eai-classification-default`, **DRAFT-Semantik**) wird automatisch geladen. Um es
zu überschreiben, legen Sie eine JSON-Datei mit `"pack_kind": "classification-profile"` in
`IGA_CONTENT_PATH` (Standard `~/.iga/content/`). Die Datei muss alle 36 Zellen abdecken; ein Pack mit
derselben `framework_id` überschreibt das eingebaute.

```json
{
  "pack_kind": "classification-profile",
  "framework_id": "eai-classification-default",
  "version": "my-org-1.0",
  "profiles": {
    "T1.L1": {"risk_presumption": "low", "strict": false,
               "obligations": ["iso42001", "euaiact"],
               "notes": {"en": "Minimal oversight required."}},
    "T1.L2": { "..." : "..." }
  }
}
```

Content Packs (Lückenzuordnungen für regulatorische Rahmenwerke) und Profile Packs koexistieren im
selben Verzeichnis; der Loader unterscheidet anhand von `pack_kind`.

### JSON-Schema für externe Producer

`schemas/eai-classification.v1.schema.json` (Repo-Wurzel) liefert eine JSON-Schema-Definition
(draft/2020-12), die Partner-Producer zur Validierung vor der Veröffentlichung nutzen können. Der
Python-Parser in `classification.py` ist die maßgebliche Quelle; `jsonschema` ist keine deklarierte
Projektabhängigkeit.

---

## Workshop-Modus (T-B3/T-B4)

`iga workshop run` ist das Live-**Kunden-Workshop-Werkzeug**: auf einem Laptop am Beamer ausführen,
auf ein Klassifikationsdokument richten. Es stellt jeden Anwendungsfall großformatig und kontraststark
dar und schreibt zugleich pro Anwendungsfall eine Übergabeunterlage auf die Platte. Der gesamte
Zyklus (Beamer-Darstellung plus Artefakterzeugung) zielt auf **unter 2 Minuten je Anwendungsfall**.
Seit v0.22.0 ist das empfohlene Verwahrmodell **kundenverankert**: Der Kunde signiert das Manifest
mit einem auf seiner Hardware erzeugten Schlüssel; presidio gegensigniert als Assessor in einem
separaten Attestierungsdokument.

### Offline-fähig

Der Workshop-Modus ist für **luftabgeschottete (air-gapped) Kundenstandorte** ausgelegt. Er umgeht
ausdrücklich die CVE-/Abhängigkeitsprüfung beim Start (`pip-audit` braucht Netzzugang; an einem
air-gapped Standort würde es hängen, in einen Timeout laufen und eine störende „inconclusive"-Warnung
ausgeben). Die Umgehung der Dep-Prüfung erfolgt automatisch, sobald der Unterbefehl `workshop` erkannt
wird; kein `--no-dep-check`-Flag nötig. Die Sicherheitslage bleibt gewahrt, indem `pip-audit` vor der
Sitzung auf der Maschine des Betreibers läuft.

### Beispiel

```bash
# Übergabeunterlagen für alle Anwendungsfälle eines Klassifikationsdokuments erzeugen,
# auf Deutsch (Standard), Ausgabe nach ./workshop-out/<datum>/.
iga workshop run \
    --file classification.json \
    --lang de

# Nur für ausgewählte Anwendungsfälle erzeugen.
iga workshop run \
    --file medical.json \
    --select infusion-pump-dosing \
    --select surgical-robotics \
    --out /tmp/workshop-2026/

# Antworten vorbelegen (ein Assessor hat zuvor ein Formular ausgefüllt).
iga workshop run \
    --file classification.json \
    --answers answers.json

# Leise: nur Artefakte schreiben, keine Beamer-Ausgabe.
iga workshop run --file classification.json --quiet
```

Das Format von `answers.json` lautet:

```json
{
  "fraud-scoring": {
    "affirm": ["S1", "S2", "S3", "D1", "D2"],
    "skip":   ["I4", "I5"]
  }
}
```

### Artefakt-Aufbau je Anwendungsfall

```
workshop-out/<datum>/<use_case_id>/
  report.de.md       Markdown-Übergabe (lokalisiert)
  report.json        Volles Bewertungs-JSON + Klassifikations-Provenienzblock
  sign.py            Eigenständiger Owner-Signer für Kunden
  SIGNING.md         Zweisprachiges Signier-Zeremonie-Runbook
  assessor.pub       Öffentlicher Presidio-Assessor-Schlüssel, falls mitgeliefert/abgeleitet
  manifest.json      Inhaltlich gehashtes Manifest (presidio-hardened/workshop-leavebehind@1)
  manifest.sig       Ed25519-Detached-Signatur (UNSIGNED-Marker, falls kein Schlüssel angegeben)
  attestation.json   Optionale Presidio-Assessor-Attestierung
  attestation.content.json
```

`manifest.json` hält fest: Werkzeugversion, Zell-ID, Risikoklasse, Sprache, content_hash des
Profil-Packs, SHA-256 jedes Artefakts und ob das Artefakt signiert ist.

### Customer-Owner-Signatur und Presidio-Attestierung

Erzeugen Sie das Customer-Owner-Schlüsselpaar auf Kunden-Hardware. Der private Schlüssel wird mit
Modus `0600` erstellt; nur der öffentliche Schlüssel geht an presidio für den Engagement-Trust-Store:

```bash
iga workshop keygen --out customer-key.hex --signer "ACME GmbH"
```

Nachdem `iga workshop run` die Übergabeunterlage geschrieben hat, signiert der Kunde das Manifest
als Owner:

```bash
iga workshop sign \
    --dir workshop-out/2026-07-04/infusion-pump-dosing/ \
    --key customer-key.hex \
    --signer "ACME GmbH"
```

Presidio gegensigniert anschließend das kundensignierte Manifest als Assessor. Die Attestierung ist
ein separates `workshop-attestation@1`-Nachweisdokument, das an den Manifest-Hash gebunden ist:

```bash
iga workshop attest \
    --dir workshop-out/2026-07-04/infusion-pump-dosing/ \
    --engagement hc-workshop-2026-001 \
    --sign-key ~/.iga/workshop-assessor.key \
    --signer presidio-hardened-ikigov-assess
```

### Eine Übergabeunterlage prüfen (Kundenseite)

Der Kunde prüft seine Owner-Signatur und, wenn erforderlich, die Presidio-Assessor-Attestierung:

```bash
# Das Artefakt im Verzeichnis infusion-pump-dosing/ prüfen.
iga workshop verify \
    --dir workshop-out/2026-07-04/infusion-pump-dosing/ \
    --pubkey <customer-public-key>

# Eine gültige, an das Manifest gebundene Presidio-Attestierung verlangen.
iga workshop verify \
    --dir workshop-out/2026-07-04/infusion-pump-dosing/ \
    --pubkey <customer-public-key> \
    --require-attestation \
    --attestation-pubkey <presidio-assessor-public-key>

# Maschinenlesbares JSON-Ergebnis.
iga workshop verify \
    --dir workshop-out/2026-07-04/infusion-pump-dosing/ \
    --pubkey <customer-public-key> \
    --quiet
```

Exit 0, wenn alle Artefakt-Hashes und die Signatur verifizieren; sonst Exit 1 (fail-closed).

#### Benannte Delegationskette (v0.23.0)

Die Linie Customer-Signatur → Manifest-Hash → Presidio-Attestierung wird als explizite
**Delegationskette** offengelegt: eine geordnete Liste benannter Glieder, jedes mit `role`,
`signer`, dem, was es `signs`, und dem Hash, den es `reference`s. `--show-chain` läuft die
Kette Glied für Glied ab, mit je eigenem Fehlergrund pro Glied (`owner-sig-invalid`,
`owner-key-mismatch`, `assessor-missing-key` sowie jeder Attestierungsgrund wie
`attests-manifest-mismatch`); `--require-chain` schlägt zusätzlich fail-closed fehl, wenn
kein Owner-Glied vorhanden ist. Dies ist **additiv und abgeleitet** — die Kette wird zur
Prüfzeit aus dem vorhandenen Owner-Block, `manifest.sig` und der Attestierung
zusammengesetzt, sodass vor v0.23.0 erzeugte Manifeste (die keine Kette tragen) unverändert
verifizieren.

```bash
iga workshop verify \
    --dir workshop-out/2026-07-04/infusion-pump-dosing/ \
    --pubkey <customer-public-key> \
    --attestation-pubkey <presidio-assessor-public-key> \
    --show-chain --quiet
```

---

## Sicherheit

Siehe [SECURITY.md](SECURITY.md) für die vollständige Sicherheitsrichtlinie.

In das Werkzeug eingebaute Sicherheitskontrollen:
- Eingabevalidierung für alle CLI-Parameter (Typ, Grenzen, Allow-List)
- HTML-Escaping aller benutzerseitig gelieferten Zeichenketten in der Berichtsausgabe
- Strukturiertes Sicherheitsereignis-Log unter `~/.iga/security.log` (keine Inhalte protokolliert, nur strukturelle Metadaten)
- CVE-Prüfung beim Start via `pip-audit` (mit `--no-dep-check` unterdrückbar)
- Ratenbegrenzung je Sitzung (Standard: 100 Bewertungen; über `IGA_MAX_ASSESSMENTS` überschreibbar)

---

## Roadmap

| Version | Thema | Status |
|---------|-------|--------|
| v0.1.0 | MVP: interaktive + parametergesteuerte Bewertung, M1–M6-Scoring, zweisprachig | Veröffentlicht |
| v0.2.0 | MCP-Server: agentenfähige Bewertungs-Engine (`iga-mcp`) | Veröffentlicht |
| v0.3.0 | Verfeinerte Gate-Bereitschaft, CI-Exit-Codes 0/2/3, `--strict`-Flag | Veröffentlicht |
| v0.4.0 | Berichtsexport in Datei (`--output`) mit Antworten je Punkt | Veröffentlicht |
| v0.5.0 | ISO/IEC-42001-Lückenanalyse auf Klausel-Ebene (`iga iso-gap`) | Veröffentlicht |
| v0.6.0 | Portfolio-Modus: Persistenz, `list`, `portfolio`, `delete` | Veröffentlicht |
| v0.7.0 | Reifegrad-Trend: Delta zwischen gespeicherten Läufen (`iga trend`) | Veröffentlicht |
| v0.8.0 | EU-AI-Act-Gate→Artikel-Zuordnung für Hochrisiko-Systeme (`iga euaiact-gap`) | Veröffentlicht |
| v0.13.0 | Externe nachweisgestützte Bestätigung: `iga assess --evidence` / `verify-evidence` + `iga_assess_with_evidence` (erster Producer: `presidio-hardened-ai`) | Veröffentlicht |
| v0.14.0 | Public-Key-Nachweisprüfung (Ed25519): Trust-Store-Einträge `{alg, public_key}` + `verify_ref`-Dispatch (`[crypto]`-Extra) | Veröffentlicht |
| v0.20.0 | Classificator-Bridge (eai-classification/v1), 36-Zellen-Profil-Pack, `iga classify` | Veröffentlicht |
| v0.21.0 T-B3 | `iga workshop`: Offline-Kunden-Workshop-Werkzeug, Ed25519-signierte Übergabeunterlagen, `workshop verify` | Veröffentlicht |
| v0.21.0 T1.4 | Vollständige deutsche Lokalisierung: alle Laufzeitausgaben über `t()`, keine rein englischen Platzhalter unter `--lang de` | Veröffentlicht |
| v0.22.0 T-B4 | Workshop-Nachweis-Souveränität: Customer-Owner-Signaturen, Standalone-Signer, Presidio-Assessor-Attestierung | Veröffentlicht |
| v0.23.0 T-B5 | Gate-Zertifikate: signiertes `gate-certificate@1`, `iga certify` / `iga verify-certificate`, Nachweisprüfung bei Ausstellung und Verifikation, benannte Workshop-Delegationsketten | Veröffentlicht |
| v0.24.0 | Wartung: abdeckungsgeführtes Fuzzing (`fuzz`-Extra, Atheris), fail-closed-Prüfungen an den JSON-Grenzen, `mcp` unterhalb 2.0 begrenzt, um das `[mcp]`-Extra zu reparieren | Veröffentlicht |

Vollständiges Versions-Deliberationslog: [PRESIDIO-REQ.md](PRESIDIO-REQ.md)

---

## Entwicklung

```bash
# Im Editable-Modus mit Dev-Abhängigkeiten installieren
pip install -e ".[dev]"

# Tests ausführen
pytest

# Linten und formatieren
ruff format .
ruff check . --fix
```

---

## Lizenz

MIT. Siehe [LICENSE](LICENSE).

---

## SDLC

Dieses Repository wird unter dem SDLC der Presidio-hardened-Familie entwickelt:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
