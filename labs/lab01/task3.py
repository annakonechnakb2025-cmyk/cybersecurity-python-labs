import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import VARIANT_NUMBER

HASH = "sha3_256"
MIN_PASSWORD_LENGTH = 14
SALT = f"{VARIANT_NUMBER:05d}"

DATA = os.path.join(os.path.dirname(__file__), "data")
USERS_FILE = os.path.join(DATA, "users.csv")
LOG_FILE = os.path.join(DATA, "log.json")


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or password == "":
        raise ValueError("Password cannot be empty")

    if salt is None or salt == "":
        raise ValueError("Salt cannot be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError("Password is too short")

    data = password + salt

    hash_value = hashlib.new(
        HASH,
        data.encode(),
    ).hexdigest()

    return hash_value


users_to_register = (
    ("user1", "JBSjdsm2334dgfbn5"),
    ("user2", "KDjdnfbvhk3sjsuwuwuwu"),
    ("user3", "Dcfldhgsgw7ww7fhdhshs"),
    ("user4", "nmsxnDNYYbnsnx3665"),
    ("user5", "Mbsvsgsgtsyyeuue8899"),
    ("user6", "xcvbsnmowi9u938kslknw73yhu"),
    ("user7", "smmdnk2893hdjkslswi3"),
    ("user8", "mDNdjn9eouee8e30wujsms"),
    ("user9", "Dsmsbdbsjhuy2uwudh737"),
    ("user10", "NDbndhgi377372bddhiddh"),
)


def create_user(username, password):
    hash_value = generate_hash(password, SALT)
    return username, hash_value


def create_users(users_list):
    try:
        os.makedirs(DATA, exist_ok=True)

        with open(
            USERS_FILE,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.writer(file)

            for username, password in users_list:
                user = create_user(username, password)
                writer.writerow(user)

    except FileNotFoundError as error:
        print(f"File not found: {error}")

    except PermissionError as error:
        print(f"Permission denied: {error}")

    except OSError as error:
        print(f"I/O error: {error}")

    except ValidationError as error:
        print(f"Validation error: {error}")

    except ValueError as error:
        print(f"Value error: {error}")


def read_users():
    users_db = []

    try:
        with open(
            USERS_FILE,
            "r",
            newline="",
            encoding="utf-8",
        ) as file:
            reader = csv.reader(file)
            # Виправлено PERF402: використання list() замість циклу append
            users_db = list(reader)

    except FileNotFoundError as error:
        print(f"File not found: {error}")

    except PermissionError as error:
        print(f"Permission denied: {error}")

    except OSError as error:
        print(f"I/O error: {error}")

    return users_db


def log_event(function):
    @wraps(function)
    def wrapper(username, password):
        result = "failure"

        # Виправлено TRY203: прибрано зайвий try...except, який просто робив raise
        success = function(username, password)

        if success:
            result = "success"

        # Виправлено DTZ005: додано таймзону UTC у datetime.now()
        event = {
            "event": "login",
            "user": username,
            "result": result,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "args": [],
            "kwargs": {},
        }

        try:
            os.makedirs(DATA, exist_ok=True)

            events = []

            if os.path.exists(LOG_FILE):
                with open(
                    LOG_FILE,
                    "r",
                    encoding="utf-8",
                ) as file:
                    content = file.read().strip()

                    if content:
                        events = json.loads(content)

            events.append(event)

            with open(
                LOG_FILE,
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    events,
                    file,
                    indent=2,
                    ensure_ascii=False,
                )

        except FileNotFoundError as error:
            print(f"File not found: {error}")

        except PermissionError as error:
            print(f"Permission denied: {error}")

        except OSError as error:
            print(f"I/O error: {error}")

        except ValueError as error:
            print(f"JSON error: {error}")

        return success

    return wrapper


users_db = []


@log_event
def login(username: str, password: str) -> bool:
    try:
        if username is None or username == "":
            raise ValueError("Username cannot be empty")

        if password is None or password == "":
            raise ValueError("Password cannot be empty")

        password_hash = generate_hash(
            password,
            SALT,
        )

        for db_username, db_hash in users_db:
            if db_username == username:
                return db_hash == password_hash

        return False

    except FileNotFoundError as error:
        print(f"File not found: {error}")
        return False

    except PermissionError as error:
        print(f"Permission denied: {error}")
        return False

    except OSError as error:
        print(f"I/O error: {error}")
        return False

    except ValidationError as error:
        print(f"Validation error: {error}")
        return False

    except ValueError:
        return False


def print_users(users):
    print("-" * 40)
    print(f"{'Username':<15} {'Password hash'}")
    print("-" * 40)

    for username, password_hash in users:
        print(f"{username:<15} {password_hash}")

    print("-" * 40)


def run():
    global users_db

    try:
        print(f"Variant: {VARIANT_NUMBER}")
        print(f"Hash: {HASH}")
        print(f"Minimum password length: {MIN_PASSWORD_LENGTH}")
        print(f"Personal salt: {SALT}")
        print()

        create_users(users_to_register)

        users_db = read_users()

        print("Users database:")
        print_users(users_db)

        print()
        print("Authentication:")

        result = login(
            "user1",
            "JBSjdsm2334dgfbn5",
        )
        print(f"user1 -> {result}")

        result = login(
            "user1",
            "",
        )
        print(f"user1 -> {result}")

        result = login(
            "cat1",
            "bBhhnmem494949",
        )
        print(f"cat1 -> {result}")

    except FileNotFoundError as error:
        print(f"File not found: {error}")

    except PermissionError as error:
        print(f"Permission denied: {error}")

    except OSError as error:
        print(f"I/O error: {error}")

    except ValidationError as error:
        print(f"Validation error: {error}")

    except ValueError as error:
        print(f"Value error: {error}")
