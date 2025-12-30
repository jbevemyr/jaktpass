# Jaktpass

En liten Seterra-liknande webapp för att träna på var jaktpass ligger på en uppladdad kartbild.

- **Backend**: Yaws + Erlang, en enda appmod: `jaktpass_appmod.erl` (routing under `/api`)
- **Frontend**: minimal SPA som statiska filer i `priv/www` (serveras av Yaws docroot)
- **Persistens**: filer på disk (JSON + bildfil) under `JAKTPASS_DATA_DIR` (default `./priv/data`)
- **Admin**: Basic Auth för alla endpoints under `/api/admin/*`

## Miljövariabler

- **`JAKTPASS_DATA_DIR`**: datakatalog (default `./priv/data`)
- **`JAKTPASS_ADMIN_USER`**: admin username (default `admin`)
- **`JAKTPASS_ADMIN_PASS`**: admin password (default `admin`)
- **`JAKTPASS_COOKIE_SECURE`**: sätt till `true` i production (HTTPS) för att lägga `Secure` på v2-cookie (default `false`)

Exempel:

```bash
export JAKTPASS_DATA_DIR=./priv/data
export JAKTPASS_ADMIN_USER=admin
export JAKTPASS_ADMIN_PASS=admin
```

## Filstruktur på disk

```
priv/data/
  sets/
    <setId>/
      meta.json
      image.<ext>
```

`meta.json` innehåller:

- `set`: `{id, name, createdAt}`
- `image`: `{filename, width, height, uploadedAt}` (om uppladdad)
- `stands`: `[{id, name, note?, x, y, createdAt, updatedAt}]`
  
**OBS:** Områden (areas) är borttagna i denna variant.

## Yaws-konfiguration (snippet)

Lägg t.ex. detta i din `yaws.conf`:

```erlang
<server jaktpass>
    port = 8080
    listen = 0.0.0.0
    docroot = /ABSOLUT/PATH/till/jaktpass/priv/www
    appmods = <"/api", jaktpass_appmod>
</server>
```

Se till att `jaktpass_appmod.beam` finns på Erlang code path när Yaws startar (t.ex. via `-pa` eller genom att lägga den i en katalog Yaws laddar).

## V2 (multi-admin) – separat från v1

V2 ligger parallellt med nuvarande Basic Auth-läge (v1). V1 fortsätter fungera som innan.

- **V2 UI**: `"/v2/"` (hash-routing)
  - Registrering: `"/v2/#/register"`
  - Login: `"/v2/#/login"`
  - Admin (mina set): `"/v2/#/admin"`
  - Publikt quiz via share-länk: `"/v2/#/quiz/<shareId>"`

### V2 API (session-cookie)
- `POST /api/v2/register` `{email, password}` → skapar admin + sätter cookie
- `POST /api/v2/login` `{email, password}` → sätter cookie
- `POST /api/v2/logout` → rensar cookie
- `GET /api/v2/me` → `{admin}`
- `GET /api/v2/sets` (auth) → lista dina set
- `POST /api/v2/sets` (auth) `{name}` → skapar set + shareId
- `POST /api/v2/sets/:setId/share` (auth) → skapar/returnerar share-länk
- `GET /api/v2/quiz/:shareId?mode=rand10|randHalf|all` (publikt) → quiz-pack
- `GET /api/v2/media/shares/:shareId/image` (publikt) → bildfil

### V2 data på disk
Ligger under `JAKTPASS_DATA_DIR` (default `./priv/data`) i en separat underkatalog:

```
priv/data/
  v2/
    admin_index.json
    admins/<adminId>/admin.json
    admins/<adminId>/sets/<setId>/meta.json
    admins/<adminId>/sets/<setId>/image.<ext>
    sessions/<token>.json
    shares/<shareId>.json
```

## Python-server (för lokal test)

Detta repo innehåller även en **deps-fri Python 3-server** som implementerar samma API + serverar samma SPA, för att du enkelt ska kunna testa lokalt utan Yaws.

Kör:

```bash
python3 pyserver/jaktpass_pyserver.py --port 8000
```

Öppna sedan:

- SPA: `http://127.0.0.1:8000/`
- API: `http://127.0.0.1:8000/api/...`

Den använder samma env vars som Yaws:

- `JAKTPASS_DATA_DIR` (default `./priv/data`)
- `JAKTPASS_ADMIN_USER` / `JAKTPASS_ADMIN_PASS` (default `admin`/`admin`)

## API-exempel med curl

Notera: alla svar är JSON i formatet:

- OK: `{"ok":true,"data":...}`
- Fel: `{"ok":false,"error":"...","details":...}`

### Skapa set (admin)

```bash
curl -i \
  -u "$JAKTPASS_ADMIN_USER:$JAKTPASS_ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -d '{"name":"Mitt set"}' \
  http://localhost:8080/api/admin/sets
```

### Radera set (admin)

```bash
curl -i \
  -u "$JAKTPASS_ADMIN_USER:$JAKTPASS_ADMIN_PASS" \
  -X DELETE \
  http://localhost:8080/api/admin/sets/<setId>
```

### Lista set (publikt)

```bash
curl -s http://localhost:8080/api/sets
```

### Hämta ett set (publikt)

```bash
curl -s http://localhost:8080/api/sets/<setId>
```

### Ladda upp bild (admin)

```bash
curl -i \
  -u "$JAKTPASS_ADMIN_USER:$JAKTPASS_ADMIN_PASS" \
  -F "file=@/ABSOLUT/PATH/karta.png" \
  http://localhost:8080/api/admin/sets/<setId>/image
```

### Hämta bild (publikt)

```bash
curl -i http://localhost:8080/api/media/sets/<setId>/image
```

### Skapa pass/stand (admin)

```bash
curl -i \
  -u "$JAKTPASS_ADMIN_USER:$JAKTPASS_ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -d '{"name":"Pass 1","x":0.42,"y":0.33,"note":"valfritt"}' \
  http://localhost:8080/api/admin/sets/<setId>/stands
```

### Ändra pass/stand (admin)

```bash
curl -i \
  -u "$JAKTPASS_ADMIN_USER:$JAKTPASS_ADMIN_PASS" \
  -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"name":"Nytt namn","x":0.5,"y":0.5}' \
  http://localhost:8080/api/admin/stands/<standId>
```

### Radera pass/stand (admin)

```bash
curl -i \
  -u "$JAKTPASS_ADMIN_USER:$JAKTPASS_ADMIN_PASS" \
  -X DELETE \
  http://localhost:8080/api/admin/stands/<standId>
```

### Skapa område (admin)

```bash
echo "Områden (areas) är borttagna i denna variant."
```

### Hämta quiz-pack (publikt)

```bash
curl -s "http://localhost:8080/api/sets/<setId>/quiz?mode=rand10"
curl -s "http://localhost:8080/api/sets/<setId>/quiz?mode=randHalf"
curl -s "http://localhost:8080/api/sets/<setId>/quiz?mode=all"
```

## Frontend

Öppna `http://localhost:8080/` efter att du startat Yaws med `docroot` pekandes på `priv/www`.


