"""Проверяет, что базы, записанные НАШИМ ядром, читаются сторонней реализацией.

Обратная сторона tests/foreign_fixtures.rs: там наш core читает чужие файлы, здесь
чужой код читает наши. Вместе они закрывают оба направления совместимости с KDBX4.

Запускает `cargo run --example write_roundtrip_dbs`, который пишет базы во временную
директорию, затем открывает каждую через pykeepass и сверяет содержимое.

Это отдельный шаг, а НЕ часть `cargo test`: Python не должен быть обязательной
зависимостью для сборки и прогона тестов Rust-крейта.

Использование (из корня pass-rust-core):
    .venv/Scripts/python.exe tools/kdbx-oracle/verify_roundtrip.py
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    # Windows-консоль не utf-8 по умолчанию
    sys.stdout.reconfigure(encoding="utf-8")

from pykeepass import PyKeePass

REPO_ROOT = Path(__file__).resolve().parents[2]

# Должно совпадать с константами в examples/write_roundtrip_dbs.rs
PASSWORD = "test-pass-1234"
ATTACHMENT_NAME = "notes.txt"
ATTACHMENT_DATA = b"example doc\n2 lines\n"
TOTP_URL = "otpauth://totp/server?secret=JBSWY3DPEHPK3PXP&issuer=demo&algorithm=SHA1&digits=6&period=30"

EXPECTED_TITLES = ["Email", "GitHub", "Server"]
# Наше ядро называет корневую группу по имени базы (database_name в NewDatabase),
# а не фиксированным "Root", как шаблон pykeepass. Это поведение нашего кода, не формата.
EXPECTED_GROUPS = ["RoundTripDb", "Work"]
EXPECTED_PASSWORDS = {
    "GitHub": "gh-secret-1",
    "Email": "mail-secret-2",
    "Server": "srv-secret-3",
}


def write_databases(out_dir):
    """Просит наше ядро записать базы. Возвращает список (путь, шифр, kdf, key-file)."""
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--example",
            "write_roundtrip_dbs",
            "--",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("cargo run упал:\n%s\n%s" % (result.stdout, result.stderr))
        raise SystemExit(1)

    databases = []
    for line in result.stdout.splitlines():
        # Пример печатает: путь|шифр|kdf|key-file (последнее поле может быть пустым)
        parts = line.strip().split("|")
        if len(parts) == 4 and parts[0].endswith(".kdbx"):
            path, cipher, kdf, key_file = parts
            databases.append((path, cipher, kdf, key_file or None))

    if not databases:
        print("пример не напечатал ни одной базы; вывод был:\n%s" % result.stdout)
        raise SystemExit(1)
    return databases


def verify(path, key_file):
    """Открывает базу сторонней реализацией и сверяет содержимое."""
    kp = PyKeePass(path, password=PASSWORD, keyfile=key_file)

    titles = sorted(entry.title for entry in kp.entries)
    assert titles == EXPECTED_TITLES, "записи: %s" % titles

    groups = sorted(group.name for group in kp.groups)
    assert groups == EXPECTED_GROUPS, "группы: %s" % groups

    # Пароли — protected-значения: если inner-stream шифр записан неверно,
    # расшифровка даст мусор
    for title, expected in EXPECTED_PASSWORDS.items():
        entry = kp.find_entries(title=title, first=True)
        assert entry is not None, "запись %s не найдена" % title
        assert entry.password == expected, "%s: пароль %r" % (title, entry.password)

    server = kp.find_entries(title="Server", first=True)
    assert server.parentgroup.name == "Work", "Server не в группе Work"

    # TOTP — тоже protected-значение
    assert server.otp == TOTP_URL, "otp: %r" % server.otp

    # Аттачмент проверяет inner header (binaries) и ссылку из записи
    attachments = [(a.filename, a.data) for a in server.attachments]
    assert attachments == [(ATTACHMENT_NAME, ATTACHMENT_DATA)], "аттачменты: %s" % (
        [(name, len(data)) for name, data in attachments],
    )


def main():
    out_dir = Path(tempfile.mkdtemp(prefix="okp_roundtrip_"))
    try:
        print("Наше ядро пишет базы в %s" % out_dir)
        databases = write_databases(out_dir)

        for path, cipher, kdf, key_file in databases:
            verify(path, key_file)
            print(
                "  OK  %-38s %-9s %-9s%s"
                % (
                    Path(path).name,
                    cipher,
                    kdf,
                    "  + key-file" if key_file else "",
                )
            )

        print("\nВсе %d баз, записанных нашим ядром, читаются pykeepass." % len(databases))
        return 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
