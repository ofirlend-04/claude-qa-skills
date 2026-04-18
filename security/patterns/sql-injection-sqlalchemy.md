# Pattern: SQL injection via f-string / `.format()` / `text()` concatenation

**Rules:** E1, E2, E3
**Severity:** P0
**Seen in:** Any Python codebase touched by someone who learned SQL before parameterised queries were fashionable. Also in rushed migrations from ORMs to "raw for performance".

## Incident story

**Classic** — this is the oldest vulnerability in web apps (OWASP #1 for a decade). In 2017 a bug in a popular Django app allowed a user-controllable integer field to dump the users table via a single `' OR 1=1 --` injected into a raw `cursor.execute(f"...")` call.

**Modern variant** — SQLAlchemy makes it easy to write parameterised queries *and* easy to bypass them with `text()` + string concatenation. The pattern "I just need a quick raw query for this one case" → "it works on my machine" → "production compromised".

## Bad code

### Python `cursor.execute` with f-string

```python
def get_user(email: str):
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
    return cursor.fetchone()

# Attacker calls with email = "' OR 1=1 --"
# Result: SELECT * FROM users WHERE email = '' OR 1=1 --'
# Returns the entire users table.
```

### `.format()` variant

```python
cursor.execute("SELECT * FROM users WHERE email = '{}'".format(email))
```

### SQLAlchemy `text()` with concat

```python
from sqlalchemy import text

result = db.execute(text("SELECT * FROM orders WHERE user_id = " + str(user_id)))
# str(user_id) is not validation. If user_id is "1 UNION SELECT password FROM users" it fires.
```

### Node template literal

```ts
await db.query(`SELECT * FROM users WHERE id = ${userId}`);
// userId = "1 OR 1=1" dumps the table.
```

### Indirect — string building

```python
order_by = request.args.get("sort", "id")
query = f"SELECT * FROM items ORDER BY {order_by}"
cursor.execute(query)
# ORDER BY is rarely parameterisable — attacker injects a subquery.
# Use a strict allowlist.
```

## Good code

### Python DB-API (psycopg, sqlite3, mysql.connector)

```python
cursor.execute(
    "SELECT * FROM users WHERE email = %s",
    (email,),
)
```

### SQLAlchemy — ORM (best)

```python
from sqlalchemy import select

stmt = select(User).where(User.email == email)
result = db.execute(stmt).scalar_one_or_none()
```

### SQLAlchemy — `text()` with bound parameters

```python
from sqlalchemy import text

result = db.execute(
    text("SELECT * FROM orders WHERE user_id = :uid"),
    {"uid": user_id},
)
```

### Node `pg`

```ts
await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
```

### Node Knex

```ts
await knex('users').where({ id: userId }).first();
// NEVER: knex.raw(`... ${userId} ...`)
```

### For ORDER BY / column names (not parameterisable)

Allowlist:

```python
ALLOWED_SORTS = {"id", "name", "created_at"}
sort = request.args.get("sort", "id")
if sort not in ALLOWED_SORTS:
    abort(400)
stmt = text(f"SELECT * FROM items ORDER BY {sort}")   # now safe — allowlisted
```

## Detection

`auto_audit.py` flags:

```regex
# E1 — f-string in execute
\.execute\s*\(\s*f(['"])[^'"]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|VALUES)[^'"]*\{[^}]+\}[^'"]*\1

# E1b — .format() in execute
\.execute\s*\(\s*['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\.\s*format\s*\(

# E2 — text() + concat or f-string
\btext\s*\(\s*(['"][^'"]*['"]\s*\+|f['"][^'"]*\{[^}]+\})

# E3 — Node template literal in query/raw
\.(query|raw|execute)\s*\(\s*`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}[^`]*`
```

## Testing

```bash
# Old-school
curl "https://your.site/api/items?id=1' OR '1'='1"
curl "https://your.site/api/items?sort=id; DROP TABLE users--"

# Automated
sqlmap -u "https://your.site/api/items?id=1" --batch
```

## Mitigations beyond parameterisation

- **Least privilege DB user** — read-only where read-only works. The blast radius of a SQLi shrinks dramatically.
- **Separate DBs per tenant** where feasible. A SQLi that dumps one customer's data is painful; one that dumps everyone's is existential.
- **WAF** — not a fix, but catches naive attacks.
- **Logging** — flag queries that return an anomalous number of rows.

## References

- OWASP ASVS V5 — Input Validation
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- SQLAlchemy docs — [Using textual SQL](https://docs.sqlalchemy.org/en/20/core/tutorial.html#using-textual-sql) (see "using bound parameters")
