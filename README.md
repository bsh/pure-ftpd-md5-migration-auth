# Pure-FTPd Legacy MD5 MySQL Auth Migration Helper

A small external authentication helper for **Pure-FTPd + MySQL/MariaDB** installations that still have FTP passwords stored as legacy 32-character MD5 hashes.

It allows existing users to keep logging in with their current FTP passwords after a Debian/Pure-FTPd upgrade, while transparently migrating their stored password hash to a modern `crypt(3)` SHA-512 hash on first successful login.

## Why this exists

Older Pure-FTPd MySQL setups often used this style of configuration:

```text
MYSQLCrypt md5
```

with passwords stored in the database as 32-character hexadecimal MD5 hashes, for example:

```text
9d3e211927dfe1f410d2b633d4c8e8df
```

After upgrading Debian/Pure-FTPd, these legacy hashes may stop working. Users then receive errors such as:

```text
530 Login authentication failed
```

even though their password is correct.

The clean long-term solution is to use a stronger hash format such as SHA-512 `crypt`, for example:

```text
$6$rounds=5000$...
```

However, converting existing accounts normally requires knowing each user's plaintext password or forcing every user to reset their FTP password.

This helper avoids that forced reset.

## How it works

Pure-FTPd's normal MySQL authentication only asks the database for stored account fields. The SQL queries can access the username, IP address and similar values, but they do **not** receive the plaintext password entered by the FTP client.

Because of that, a SQL function alone cannot verify:

```sql
MD5(entered_password) = stored_hash
```

The solution is to use **Pure-FTPd external authentication** through `pure-authd`.

With external authentication:

1. Pure-FTPd receives a login attempt.
2. `pure-authd` calls this helper script.
3. The script receives the submitted username and password through environment variables.
4. The script looks up the user in the existing MySQL/MariaDB `ftpd` table.
5. If the stored password is a legacy 32-character MD5 hash, the script checks it against the submitted password.
6. If authentication succeeds, the script returns `auth_ok` to Pure-FTPd.
7. The script then migrates the stored password to a SHA-512 `crypt` hash.
8. Future logins for that user use the new hash.

This gives a gradual, login-driven migration path:

```text
legacy MD5 hash -> successful login -> SHA-512 crypt hash
```

No mass password reset is required.

## Supported password formats

The helper can handle these formats:

| Stored format | Example | Behavior |
|---|---|---|
| Legacy MD5 hex | `9d3e211927dfe1f410d2b633d4c8e8df` | Verifies with `MD5(password)` and migrates to SHA-512 `crypt` |
| SHA-512 crypt | `$6$rounds=5000$...` | Verifies directly |
| Other `crypt(3)` hashes | `$1$...`, `$5$...`, etc. | Verifies through `crypt(3)` if supported by the OS |
| Cleartext | `plainpassword` | Optional transitional support; migrates on successful login |

## Important security notes

This is intended as a **migration helper**, not as a reason to keep weak hashes forever.

Recommended final state:

```text
MYSQLCrypt crypt
```

with all passwords stored as SHA-512 `crypt` hashes such as:

```text
$6$...
```

Do not keep FTP passwords in cleartext long-term.

Also remember that plain FTP transmits credentials without encryption. If possible, use FTPS/SFTP or restrict FTP access appropriately.

## Tested environment

This was created for a Debian system using:

```text
pure-ftpd-mysql
pure-authd
MariaDB/MySQL
Python 3
python3-pymysql
```

The database table used in the examples is:

```text
pureftpd.ftpd
```

with fields similar to:

```text
User
Password
Uid
Gid
Dir
status
ipaccess
```

Adjust table and column names in the script if your schema differs.

## Before you start: make a backup

Create a database backup before changing anything:

```bash
mysqldump -u root -p pureftpd ftpd > /root/pureftpd-ftpd-before-auth-migration.sql
```

It is also useful to save the current Pure-FTPd configuration:

```bash
tar czf /root/pure-ftpd-config-before-auth-migration.tgz /etc/pure-ftpd
```

## Check the password column size

Legacy MD5 hashes are only 32 characters long.

SHA-512 `crypt` hashes are much longer, often around 90-120 characters. If your `Password` column is `CHAR(32)` or `VARCHAR(32)`, the new hashes will be truncated and logins will fail.

Check the current column definition:

```bash
mysql -u root -p pureftpd -e "SHOW FULL COLUMNS FROM ftpd LIKE 'Password';"
```

or:

```bash
mysql -u root -p pureftpd -e "SHOW CREATE TABLE ftpd\G"
```

If the column is too small, increase it:

```bash
mysql -u root -p pureftpd -e "
ALTER TABLE ftpd
MODIFY Password VARCHAR(255) NOT NULL;
"
```

Verify:

```bash
mysql -u root -p pureftpd -e "
SHOW FULL COLUMNS FROM ftpd LIKE 'Password';
"
```

## Install dependencies

```bash
apt update
apt install -y python3-pymysql
```

## Install the helper script

Create the script:

```bash
nano /usr/local/sbin/pureftpd-auth-migrate-md5.py
```

Example script:

```python
#!/usr/bin/env python3
import os
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
            '''
            SELECT User, Password, Uid, Gid, Dir
            FROM ftpd
            WHERE User=%s
              AND status='1'
              AND (ipaccess='*' OR ipaccess LIKE CONCAT('%%', %s, '%%'))
            LIMIT 1
            ''',
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
            # Transitional cleartext support.
            # Remove this branch if you do not want cleartext passwords accepted.
            ok = secrets.compare_digest(password, stored)
            should_migrate = ok

        if not ok:
            response_failed()

        if should_migrate:
            new_hash = make_sha512_crypt(password)
            if new_hash:
                cur.execute(
                    '''
                    UPDATE ftpd
                    SET Password=%s
                    WHERE User=%s AND Password=%s
                    ''',
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
```

Set secure permissions:

```bash
chmod 700 /usr/local/sbin/pureftpd-auth-migrate-md5.py
chown root:root /usr/local/sbin/pureftpd-auth-migrate-md5.py
```

## Create a systemd service for pure-authd

Create:

```bash
nano /etc/systemd/system/pure-authd-md5.service
```

Content:

```ini
[Unit]
Description=Pure-FTPd external auth for legacy MD5 migration
After=network.target mariadb.service mysql.service
Before=pure-ftpd-mysql.service pure-ftpd.service

[Service]
Type=simple
RuntimeDirectory=pure-ftpd
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/pure-authd -s /run/pure-ftpd/authd-md5.sock -r /usr/local/sbin/pureftpd-auth-migrate-md5.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start it:

```bash
systemctl daemon-reload
systemctl enable --now pure-authd-md5.service
systemctl status pure-authd-md5.service
```

## Configure Pure-FTPd to use external auth

Create the ExtAuth configuration:

```bash
echo /run/pure-ftpd/authd-md5.sock > /etc/pure-ftpd/conf/ExtAuth
ln -sf ../conf/ExtAuth /etc/pure-ftpd/auth/20extauth
```

Disable the old MySQL auth symlink during migration:

```bash
ls -l /etc/pure-ftpd/auth/
rm -f /etc/pure-ftpd/auth/*mysql*
```

Keep `/etc/pure-ftpd/db/mysql.conf`, because the helper reads the MySQL connection settings from it.

Restart Pure-FTPd:

```bash
systemctl restart pure-ftpd-mysql 2>/dev/null || systemctl restart pure-ftpd
```

Check the active options:

```bash
pure-ftpd-wrapper --show-options | grep -i auth
```

You should see an external auth option pointing to your socket.

## Test migration

Before login:

```bash
mysql -u root -p pureftpd -e "
SELECT User, LEFT(Password, 20) AS pw_start, LENGTH(Password) AS pw_len
FROM ftpd
WHERE User='exampleuser';
"
```

A legacy MD5 user will look like:

```text
pw_start              pw_len
9d3e211927dfe1f410d2  32
```

Log in through FTP using the user's existing password.

After a successful login, check again:

```bash
mysql -u root -p pureftpd -e "
SELECT User, LEFT(Password, 20) AS pw_start, LENGTH(Password) AS pw_len
FROM ftpd
WHERE User='exampleuser';
"
```

You should now see something like:

```text
pw_start              pw_len
$6$rounds=5000$...    90+
```

## Logs and troubleshooting

Check the external auth service:

```bash
journalctl -u pure-authd-md5 -b -n 100 --no-pager
```

Check Pure-FTPd:

```bash
journalctl -u pure-ftpd-mysql -u pure-ftpd -b -n 100 --no-pager
```

Check that the socket exists:

```bash
ls -l /run/pure-ftpd/authd-md5.sock
```

Check that Pure-FTPd is using ExtAuth:

```bash
pure-ftpd-wrapper --show-options | grep -i auth
```

Check that the MySQL user can read and update the table:

```bash
mysql -u pureftpd -p pureftpd -e "
SELECT User, Password, Uid, Gid, Dir
FROM ftpd
LIMIT 1;
"
```

The helper needs both `SELECT` and `UPDATE` privileges on the FTP user table if you want automatic migration.

Example grants:

```sql
GRANT SELECT, UPDATE ON pureftpd.ftpd TO 'pureftpd'@'localhost';
FLUSH PRIVILEGES;
```

## Common issues

### Login still fails for every user

Verify that Pure-FTPd is actually using ExtAuth:

```bash
pure-ftpd-wrapper --show-options | grep -i auth
ls -l /etc/pure-ftpd/auth/
```

If the old MySQL auth symlink is still active, remove it during migration:

```bash
rm -f /etc/pure-ftpd/auth/*mysql*
systemctl restart pure-ftpd-mysql 2>/dev/null || systemctl restart pure-ftpd
```

### Password changes to `$6$...` but login fails afterwards

The `Password` column is probably too small and the hash was truncated.

Fix it:

```bash
mysql -u root -p pureftpd -e "
ALTER TABLE ftpd
MODIFY Password VARCHAR(255) NOT NULL;
"
```

Then restore from backup or reset the affected password.

### The helper can read users but cannot migrate hashes

The MySQL account probably has `SELECT` permission but not `UPDATE`.

Grant update permission:

```sql
GRANT SELECT, UPDATE ON pureftpd.ftpd TO 'pureftpd'@'localhost';
FLUSH PRIVILEGES;
```

### The script cannot connect to MySQL/MariaDB

Check `/etc/pure-ftpd/db/mysql.conf`:

```bash
grep -Ei '^(MYSQLServer|MYSQLPort|MYSQLSocket|MYSQLUser|MYSQLPassword|MYSQLDatabase)' /etc/pure-ftpd/db/mysql.conf
```

If your database uses a Unix socket, make sure `MYSQLSocket` is correct.

## Final state after migration

After most or all users have logged in and their hashes have been migrated, you can return to standard Pure-FTPd MySQL authentication.

Recommended final configuration:

```text
MYSQLCrypt crypt
```

Re-enable MySQL auth:

```bash
rm -f /etc/pure-ftpd/auth/*extauth*
ln -sf ../conf/MySQLConfigFile /etc/pure-ftpd/auth/30mysql
sed -i 's/^MYSQLCrypt.*/MYSQLCrypt crypt/' /etc/pure-ftpd/db/mysql.conf
systemctl restart pure-ftpd-mysql 2>/dev/null || systemctl restart pure-ftpd
```

Confirm that no legacy MD5 hashes remain:

```bash
mysql -u root -p pureftpd -e "
SELECT COUNT(*) AS legacy_md5_passwords
FROM ftpd
WHERE Password REGEXP '^[0-9a-fA-F]{32}$';
"
```

If the count is `0`, migration is complete.

You can then stop and disable the external auth service:

```bash
systemctl disable --now pure-authd-md5.service
```

Optionally remove the migration helper:

```bash
rm -f /usr/local/sbin/pureftpd-auth-migrate-md5.py
rm -f /etc/systemd/system/pure-authd-md5.service
systemctl daemon-reload
```

## Rollback

If something goes wrong, restore the previous Pure-FTPd authentication method.

For example, to remove ExtAuth and restore MySQL auth:

```bash
rm -f /etc/pure-ftpd/auth/*extauth*
ln -sf ../conf/MySQLConfigFile /etc/pure-ftpd/auth/30mysql
systemctl restart pure-ftpd-mysql 2>/dev/null || systemctl restart pure-ftpd
```

Restore the database backup if needed:

```bash
mysql -u root -p pureftpd < /root/pureftpd-ftpd-before-auth-migration.sql
```

Restore the Pure-FTPd config backup if needed:

```bash
tar xzf /root/pure-ftpd-config-before-auth-migration.tgz -C /
systemctl restart pure-ftpd-mysql 2>/dev/null || systemctl restart pure-ftpd
```

## License

[MIT](./LICENSE)