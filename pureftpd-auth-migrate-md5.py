#!/usr/bin/env python3
# Pure-FTPd legacy MD5 MySQL authentication migration helper
# https://github.com/bsh/pure-ftpd-md5-migration-auth
#
# Copyright (c) 2026 bsh
# Licensed under the MIT License.
import sys
import hashlib
import secrets
import pymysql

try:
    import crypt
except Exception:
    crypt = None


MYSQL_CONF = "/etc/pure-ftpd/db/mysql.conf"


def read_mysql_conf(path):
    cfg = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                cfg[parts[0]] = parts[1].strip()
    return cfg


def response_not_found():
    print("auth_ok:0")
    print("end")
    sys.exit(0)


def response_failed():
    print("auth_ok:-1")
    print("end")
    sys.exit(0)


def response_ok(uid, gid, directory):
    print("auth_ok:1")
    print(f"uid:{int(uid)}")
    print(f"gid:{int(gid)}")
    print(f"dir:{directory}")
    print("slow_tilde_expansion:1")
    print("end")
    sys.exit(0)


def is_md5_hex(value):
    if len(value) != 32:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def make_sha512_crypt(password):
    if crypt is None:
        return None
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))


def verify_crypt(password, stored_hash):
    if crypt is None:
        return False
    calculated = crypt.crypt(password, stored_hash)
    return calculated is not None and secrets.compare_digest(calculated, stored_hash)


account = os.environ.get("AUTHD_ACCOUNT", "")
password = os.environ.get("AUTHD_PASSWORD", "")
remote_ip = os.environ.get("AUTHD_REMOTE_IP", "")

if not account or password == "":
    response_not_found()

cfg = read_mysql_conf(MYSQL_CONF)

connect_args = {
    "user": cfg.get("MYSQLUser"),
    "password": cfg.get("MYSQLPassword"),
    "database": cfg.get("MYSQLDatabase"),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}

if cfg.get("MYSQLSocket"):
    connect_args["unix_socket"] = cfg.get("MYSQLSocket")
else:
    connect_args["host"] = cfg.get("MYSQLServer", "localhost")
    connect_args["port"] = int(cfg.get("MYSQLPort", "3306"))

try:
    conn = pymysql.connect(**connect_args)
except Exception:
    response_failed()

try:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT User, Password, Uid, Gid, Dir
            FROM ftpd
            WHERE User=%s
              AND status='1'
              AND (ipaccess='*' OR ipaccess LIKE CONCAT('%%', %s, '%%'))
            LIMIT 1
            """,
            (account, remote_ip),
        )
        row = cur.fetchone()

        if not row:
            response_not_found()

        stored = str(row["Password"])
        ok = False
        should_migrate = False

        if is_md5_hex(stored):
            md5_password = hashlib.md5(password.encode("utf-8")).hexdigest()
            ok = secrets.compare_digest(md5_password.lower(), stored.lower())
            should_migrate = ok

        elif stored.startswith("$"):
            ok = verify_crypt(password, stored)

        else:
            # átmeneti cleartext támogatás, ha ilyen sor is van a DB-ben
            ok = secrets.compare_digest(password, stored)
            should_migrate = ok

        if not ok:
            response_failed()

        if should_migrate:
            new_hash = make_sha512_crypt(password)
            if new_hash:
                cur.execute(
                    """
                    UPDATE ftpd
                    SET Password=%s
                    WHERE User=%s AND Password=%s
                    """,
                    (new_hash, account, stored),
                )
                conn.commit()

        response_ok(row["Uid"], row["Gid"], row["Dir"])

except Exception:
    response_failed()
finally:
    try:
        conn.close()
    except Exception:
        pass