# BlueTodo

BlueTodo ist eine kleine Todo-App auf Rust-Basis.
Aktuell unterstützt sie Todos, Unter-Todos, Bestellnummern, Budgetierung, Deadlines, Archivierung, PDF-Upload und viele weitere kleine Helfer. Die App ist über die Zeit praxisnah für unterschiedliche Arbeitsweisen gewachsen.

## Kurz

- Weboberfläche für Todos, Aufträge und Archiv
- SQLite als lokaler Datenspeicher
- optionale PDF-Anhänge pro Eintrag
- optionales Legacy-TCP-Protokoll
- einzelnes Binary

## Start

```bash
cargo run
```

HTTP läuft standardmäßig auf `0.0.0.0:5876`.

## Installation

```bash
cargo build --release
./target/release/bluetodo
```

Für den Betrieb mit `systemd` liegen diese Dateien im Repo:

- `packaging/systemd/bluetodo.service`
- `packaging/systemd/bluetodo.env.example`
- `scripts/install-systemd.sh`

## Clients

Die Clients liegen in eigenen Repositories:

- `bluetodo-tui`
- `bluetodo-win16`
- `bluetodo-nt4ppc` (aktuell noch nicht fertig)

## Lizenz

MIT, siehe `LICENSE`.
