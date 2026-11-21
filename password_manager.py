#!/usr/bin/env python3
"""CLI-менеджер паролей: SQLite3 + Fernet + интерактивное меню."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import platform
import secrets
import shutil
import sqlite3
import string
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vault.db"
KEY_PATH = BASE_DIR / ".key"

DEFAULT_LENGTH = 16
SALT_SIZE = 16


def hash_master_password(password: str, salt: bytes) -> str:
    """Хеш мастер-пароля: SHA-256(соль + пароль)."""
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Класс DatabaseManager — работа с базой данных
# ---------------------------------------------------------------------------

class DatabaseManager:
    """Отвечает за взаимодействие с SQLite3.

    В __init__ создаётся файл базы, init_database проверяет и создаёт таблицы.
    Для мастер-пароля используется отдельная таблица master_password.
    """

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.init_database()

    def init_database(self) -> None:
        """Создать таблицы, если их ещё нет."""
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS master_password (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                salt         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS passwords (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                title    TEXT NOT NULL COLLATE NOCASE UNIQUE,
                login    TEXT NOT NULL,
                password BLOB NOT NULL
            );
            """
        )
        self.connection.commit()
        self._migrate_legacy_tables()

    def _table_exists(self, name: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
            ).fetchone()
            is not None
        )

    def _migrate_legacy_tables(self) -> None:
        """Перенести данные из старых таблиц meta/entries, если они остались."""
        if not (self._table_exists("meta") and self._table_exists("entries")):
            return

        if not self.has_master_password():
            salt = self.connection.execute(
                "SELECT value FROM meta WHERE key = 'salt'"
            ).fetchone()
            digest = self.connection.execute(
                "SELECT value FROM meta WHERE key = 'master_hash'"
            ).fetchone()
            if salt and digest:
                self.connection.execute(
                    "INSERT INTO master_password (id, password_hash, salt) VALUES (1, ?, ?)",
                    (digest["value"], salt["value"]),
                )

        if not self.connection.execute("SELECT 1 FROM passwords LIMIT 1").fetchone():
            self.connection.execute(
                "INSERT INTO passwords (title, login, password) "
                "SELECT title, login, password FROM entries"
            )

        # Старые таблицы оставляем как резервную копию, но из схемы убираем.
        self.connection.execute("ALTER TABLE entries RENAME TO entries_legacy")
        self.connection.execute("ALTER TABLE meta RENAME TO meta_legacy")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    # -- мастер-пароль -------------------------------------------------------

    def has_master_password(self) -> bool:
        return self.get_master_password() is not None

    def get_master_password(self) -> Optional[sqlite3.Row]:
        """Вернуть сохранённый хеш мастер-пароля (или None, если его нет)."""
        return self.connection.execute(
            "SELECT id, password_hash, salt FROM master_password WHERE id = 1"
        ).fetchone()

    def set_master_password(self, password: str) -> None:
        """Установить мастер-пароль: соль + SHA-256, открытый вид не хранится."""
        salt = secrets.token_bytes(SALT_SIZE)
        digest = hash_master_password(password, salt)
        self.connection.execute(
            "INSERT INTO master_password (id, password_hash, salt) VALUES (1, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "password_hash = excluded.password_hash, salt = excluded.salt",
            (digest, base64.b64encode(salt).decode("ascii")),
        )
        self.connection.commit()

    def verify_master_password(self, password: str) -> bool:
        """Проверить введённый пароль, сравнив хеши за постоянное время."""
        row = self.get_master_password()
        if row is None:
            return False
        salt = base64.b64decode(row["salt"])
        candidate = hash_master_password(password, salt)
        return hmac.compare_digest(candidate, row["password_hash"])

    # -- записи --------------------------------------------------------------

    def add_password(self, title: str, login: str, encrypted_password: bytes) -> bool:
        """Добавить запись. False — если такое название уже есть."""
        try:
            self.connection.execute(
                "INSERT INTO passwords (title, login, password) VALUES (?, ?, ?)",
                (title.strip(), login.strip(), encrypted_password),
            )
        except sqlite3.IntegrityError:
            return False
        self.connection.commit()
        return True

    def get_password(self, title: str) -> Optional[sqlite3.Row]:
        return self.connection.execute(
            "SELECT title, login, password FROM passwords WHERE title = ?",
            (title.strip(),),
        ).fetchone()

    def list_passwords(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT title, login FROM passwords ORDER BY title COLLATE NOCASE"
        ).fetchall()

    def delete_password(self, title: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM passwords WHERE title = ?", (title.strip(),)
        )
        self.connection.commit()
        return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Класс EncryptionManager — шифрование и дешифрование
# ---------------------------------------------------------------------------

class EncryptionManager:
    """Управляет ключом .key и шифрованием через cryptography.fernet."""

    def __init__(self, key_path: Path = KEY_PATH) -> None:
        self.key_path = Path(key_path)
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            key = self.key_path.read_bytes().strip()
            try:
                Fernet(key)  # проверка корректности ключа
            except (ValueError, TypeError) as exc:
                raise RuntimeError(f"Некорректный ключ в файле {self.key_path}") from exc
            return key

        key = Fernet.generate_key()
        # Права только для владельца (на Windows chmod ограничено, но безвредно).
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(key)
        return key

    def encrypt(self, data: str) -> bytes:
        return self.fernet.encrypt(data.encode("utf-8"))

    def decrypt(self, token: bytes) -> str:
        try:
            return self.fernet.decrypt(token).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise RuntimeError(
                "Не удалось расшифровать пароль (ключ или данные повреждены)"
            ) from exc


# ---------------------------------------------------------------------------
# Класс PasswordGenerator — генерация надёжных паролей
# ---------------------------------------------------------------------------

class PasswordGenerator:
    """Создаёт случайный пароль с настраиваемыми наборами символов.

    По умолчанию длина 16 символов; можно включить/отключить заглавные,
    строчные буквы, цифры и спецсимволы.
    """

    GROUPS = {
        "lowercase": string.ascii_lowercase,
        "uppercase": string.ascii_uppercase,
        "digits": string.digits,
        "special": string.punctuation,
    }

    def __init__(
        self,
        length: int = DEFAULT_LENGTH,
        lowercase: bool = True,
        uppercase: bool = True,
        digits: bool = True,
        special: bool = True,
    ) -> None:
        self.length = length
        self.enabled = {
            "lowercase": lowercase,
            "uppercase": uppercase,
            "digits": digits,
            "special": special,
        }

    def generate(self) -> str:
        pools = [pool for name, pool in self.GROUPS.items() if self.enabled[name]]
        if not pools:
            raise ValueError("Нужно выбрать хотя бы один набор символов")
        if self.length < len(pools):
            raise ValueError(
                f"Длина ({self.length}) меньше числа выбранных наборов ({len(pools)})"
            )

        alphabet = "".join(pools)
        # Обязательно по одному символу из каждого включённого набора.
        chars = [secrets.choice(pool) for pool in pools]
        chars += [secrets.choice(alphabet) for _ in range(self.length - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)


# ---------------------------------------------------------------------------
# Класс PasswordManager — interacting с пользователем (CLI и меню)
# ---------------------------------------------------------------------------

class PasswordManager:
    """Основной класс, через который пользователь взаимодействует с приложением."""

    def __init__(self) -> None:
        self.db = DatabaseManager()
        self.encryption = EncryptionManager()

    def close(self) -> None:
        self.db.close()

    # -- служебные методы ----------------------------------------------------

    @staticmethod
    def _input(prompt: str) -> str:
        return input(prompt).strip()

    @staticmethod
    def _ask_master_password(confirm: bool = False) -> str:
        while True:
            password = getpass.getpass("Мастер-пароль: " if not confirm else "Придумайте мастер-пароль: ")
            if not password:
                print("Пароль не может быть пустым.", file=sys.stderr)
                continue
            if confirm and getpass.getpass("Повторите мастер-пароль: ") != password:
                print("Пароли не совпадают.", file=sys.stderr)
                continue
            return password

    @staticmethod
    def copy_to_clipboard(text: str) -> bool:
        """Скопировать в буфер обмена системной утилитой (без лишних зависимостей)."""
        system = platform.system()
        if system == "Windows":
            commands = (["clip"],)
        elif system == "Darwin":
            commands = (["pbcopy"],)
        else:
            commands = (
                ["wl-copy"],
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
            )

        for command in commands:
            if shutil.which(command[0]):
                try:
                    subprocess.run(
                        command, input=text, text=True, check=True, capture_output=True
                    )
                    return True
                except (OSError, subprocess.CalledProcessError):
                    continue
        return False

    # -- аутентификация ------------------------------------------------------

    def setup_master_password(self) -> None:
        """Установить мастер-пароль при первом запуске."""
        print("Первый запуск: создаём мастер-пароль.")
        password = self._ask_master_password(confirm=True)
        self.db.set_master_password(password)
        print("Мастер-пароль сохранён в виде хеша SHA-256 (с солью).")

    def authenticate(self) -> bool:
        """Запросить мастер-пароль и сравнить его хеш с сохранённым."""
        return self.db.verify_master_password(self._ask_master_password())

    # -- операции с записями -------------------------------------------------

    def add_password(
        self,
        title: Optional[str] = None,
        login: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        title = title or self._input("Название/откуда (например, Google): ")
        login = login or self._input("Логин: ")
        if not title.strip() or not login.strip():
            print("Название и логин не могут быть пустыми.", file=sys.stderr)
            return False

        if password is None:
            password = getpass.getpass("Пароль: ")
            if password != getpass.getpass("Повторите пароль: "):
                print("Пароли не совпадают.", file=sys.stderr)
                return False
        if not password:
            print("Пароль не может быть пустым.", file=sys.stderr)
            return False

        if self.db.add_password(title, login, self.encryption.encrypt(password)):
            print("Запись добавлена.")
            return True
        print(f"Запись с названием '{title.strip()}' уже существует.", file=sys.stderr)
        return False

    def get_password(self, title: Optional[str] = None, copy: bool = False) -> bool:
        title = title or self._input("Название записи: ")
        row = self.db.get_password(title)
        if row is None:
            print(f"Запись '{title.strip()}' не найдена.", file=sys.stderr)
            return False

        password = self.encryption.decrypt(row["password"])
        print(f"Название: {row['title']}")
        print(f"Логин:    {row['login']}")
        if copy:
            if self.copy_to_clipboard(password):
                print("Пароль скопирован в буфер обмена.")
            else:
                print("Не удалось обратиться к буферу обмена. Пароль ниже:")
                print(f"Пароль:   {password}")
        else:
            print(f"Пароль:   {password}")
        return True

    def list_passwords(self) -> None:
        rows = self.db.list_passwords()
        if not rows:
            print("Сохранённых записей нет.")
            return
        print("Название | Логин")
        print("-" * 40)
        for row in rows:
            print(f"{row['title']} | {row['login']}")

    def delete_password(self, title: Optional[str] = None) -> bool:
        title = title or self._input("Название записи: ")
        if self.db.delete_password(title):
            print("Запись удалена.")
            return True
        print(f"Запись '{title.strip()}' не найдена.", file=sys.stderr)
        return False

    def generate_password_interactive(self) -> None:
        """Спросить параметры, сгенерировать пароль и предложить сохранить."""
        raw_length = self._input(f"Длина пароля [{DEFAULT_LENGTH}]: ")
        try:
            length = int(raw_length) if raw_length else DEFAULT_LENGTH
        except ValueError:
            print("Длина должна быть числом.", file=sys.stderr)
            return

        settings = {}
        labels = {
            "lowercase": "строчные буквы",
            "uppercase": "заглавные буквы",
            "digits": "цифры",
            "special": "спецсимволы",
        }
        for key, label in labels.items():
            answer = self._input(f"Использовать {label}? [да/нет, по умолчанию да]: ").lower()
            settings[key] = answer not in ("нет", "no", "n")

        try:
            password = PasswordGenerator(length=length, **settings).generate()
        except ValueError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)
            return

        print(f"Новый пароль: {password}")
        if self._input("Сохранить эту запись? [да/нет]: ").lower() in ("да", "yes", "y", "д"):
            title = self._input("Название/откуда: ")
            login = self._input("Логин: ")
            if self.db.add_password(title, login, self.encryption.encrypt(password)):
                print("Запись добавлена.")
            else:
                print(f"Запись с названием '{title.strip()}' уже существует.", file=sys.stderr)

    # -- интерактивное меню --------------------------------------------------

    def show_menu(self) -> None:
        actions = {
            "1": self._menu_add,
            "2": self._menu_get,
            "3": self._menu_list,
            "4": self._menu_delete,
            "5": self.generate_password_interactive,
            "6": self._menu_copy,
        }
        while True:
            print("\n=== Менеджер паролей ===")
            print("1. Добавить пароль")
            print("2. Получить пароль")
            print("3. Список записей")
            print("4. Удалить запись")
            print("5. Сгенерировать новый пароль")
            print("6. Скопировать пароль в буфер обмена")
            print("0. Выход")
            choice = self._input("Выберите пункт: ")

            if choice == "0":
                print("До свидания!")
                break
            action = actions.get(choice)
            if action is None:
                print("Неизвестный пункт меню.", file=sys.stderr)
                continue
            try:
                action()
            except (ValueError, RuntimeError, sqlite3.Error) as exc:
                print(f"Ошибка: {exc}", file=sys.stderr)

    def _menu_add(self) -> None:
        self.add_password()

    def _menu_get(self) -> None:
        self.get_password()

    def _menu_list(self) -> None:
        self.list_passwords()

    def _menu_delete(self) -> None:
        self.delete_password()

    def _menu_copy(self) -> None:
        self.get_password(copy=True)


# ---------------------------------------------------------------------------
# CLI-обработчик
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_manager.py",
        description="Хранилище паролей: SQLite3 + Fernet. Без аргументов — интерактивное меню.",
    )
    subparsers = parser.add_subparsers(dest="command")

    add = subparsers.add_parser("add", help="добавить новую запись")
    add.add_argument("title", nargs="?", help="название/откуда")
    add.add_argument("login", nargs="?", help="логин")
    add.add_argument("password", nargs="?", help="пароль (лучше вводить по запросу)")

    get = subparsers.add_parser("get", help="получить пароль по названию")
    get.add_argument("title")
    get.add_argument("--copy", action="store_true", help="скопировать пароль в буфер обмена")

    copy = subparsers.add_parser("copy", help="скопировать пароль в буфер обмена")
    copy.add_argument("title")

    subparsers.add_parser("list", help="показать названия и логины всех записей")

    delete = subparsers.add_parser("delete", help="удалить запись по названию")
    delete.add_argument("title")

    new = subparsers.add_parser("new", help="сгенерировать новый пароль")
    new.add_argument("--length", type=int, default=DEFAULT_LENGTH, help="длина (по умолчанию 16)")
    new.add_argument("--no-lowercase", action="store_true", help="исключить строчные буквы")
    new.add_argument("--no-uppercase", action="store_true", help="исключить заглавные буквы")
    new.add_argument("--no-digits", action="store_true", help="исключить цифры")
    new.add_argument("--no-special", action="store_true", help="исключить спецсимволы")
    new.add_argument("--add", action="store_true", help="сразу сохранить пароль")
    new.add_argument("--title", help="название записи (вместе с --add)")
    new.add_argument("--login", help="логин (вместе с --add)")
    new.add_argument("--copy", action="store_true", help="скопировать пароль в буфер обмена")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    manager = PasswordManager()
    try:
        if not manager.db.has_master_password():
            manager.setup_master_password()
        elif not manager.authenticate():
            print("Неверный мастер-пароль.", file=sys.stderr)
            return 1

        if args.command is None:
            manager.show_menu()
        elif args.command == "add":
            if not manager.add_password(args.title, args.login, args.password):
                return 1
        elif args.command == "get":
            if not manager.get_password(args.title, copy=args.copy):
                return 1
        elif args.command == "copy":
            if not manager.get_password(args.title, copy=True):
                return 1
        elif args.command == "list":
            manager.list_passwords()
        elif args.command == "delete":
            if not manager.delete_password(args.title):
                return 1
        elif args.command == "new":
            generator = PasswordGenerator(
                length=args.length,
                lowercase=not args.no_lowercase,
                uppercase=not args.no_uppercase,
                digits=not args.no_digits,
                special=not args.no_special,
            )
            password = generator.generate()
            print(f"Новый пароль: {password}")
            if args.copy and manager.copy_to_clipboard(password):
                print("Пароль скопирован в буфер обмена.")
            if args.add:
                title = args.title or manager._input("Название/откуда: ")
                login = args.login or manager._input("Логин: ")
                if manager.db.add_password(title, login, manager.encryption.encrypt(password)):
                    print("Запись добавлена.")
                else:
                    print(f"Запись с названием '{title.strip()}' уже существует.", file=sys.stderr)
                    return 1
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nОперация отменена.", file=sys.stderr)
        return 130
    finally:
        manager.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
