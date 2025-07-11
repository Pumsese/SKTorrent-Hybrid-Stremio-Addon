# SKTorrent Hybrid Addon (Real-Debrid + Torrent)

## 🙏 Poděkování

Tento addon je vyvíjen na bázi původního [Sktorrent-Stremio-addon](https://github.com/JohnnyK007/Sktorrent-Stremio-addon) projektu. **Děkujeme původnímu autorovi** za vytvoření základní funkcionality pro integraci SKTorrent.eu se Stremio platformou.

---

## 📋 Přehled

**SKTorrent Hybrid Addon** je pokročilá verze původního addonu, která kombinuje **Real-Debrid službu** s torrenty ze **[SKTorrent.eu](https://sktorrent.eu)** a poskytuje:

* ⚡ **Real-Debrid integrace** s lazy loading processingem
* 🎬 **Torrent streams** ze SKTorrent.eu
* 🔐 **API klíč autentifikace** pro zabezpečení přístupu
* 🎮 **Konfigurovatelné módy streamování** (`RD_ONLY`, `BOTH`, `TORRENT_ONLY`)
* 🔄 **Proxy streaming mód** - všechna video data přes server, žádné redirecty
* 🛡️ **Maximální soukromí** - Stremio nevidí Real-Debrid URL
* 📱 **Dockerizace** s jednoduchým nasazením

## 🚀 Hlavní funkce

### Real-Debrid Features

* ✅ **Cache kontrola** - okamžité přehrání dostupného obsahu
* ✅ **Lazy processing** - RD zpracování až po výběru streamu
* ✅ **Proxy streaming** - všechna video data streamují přes váš server
* ✅ **IP protection** - Stremio nevidí Real-Debrid URL
* ✅ **Range requests podpora** - plná kompatibilita pro video přehrávání

### Sktorrent.eu Features

* ✅ **IMDB integrace** s fallback vyhledáváním
* ✅ **Multi-query systém** pro maximální pokrytí
* ✅ **Jazykové vlajky** a metadata zobrazení
* ✅ **Sezóny a epizody** s podporou různých formátů

### 🔄 Proxy Streaming Mód

Addon používá **proxy streaming** místo HTTP redirectů:

* ✅ **Žádné přímé připojení** - Stremio se nikdy nepřipojuje přímo k Real-Debrid
* ✅ **Serverová kontrola** - všechna video data prochází přes váš server
* ✅ **Skryté URL** - Real-Debrid linky zůstávají skryté před klientem
* ✅ **Range requests** - plná podpora pro video seeking a buffering
* ⚡ **Performance** - vyšší zátěž serveru, ale maximální kontrola

**Technické detaily:**
- Nahrazuje `res.redirect(302, url)` za `streamResponse.data.pipe(res)`
- Plná kompatibilita s video playery a seeking funkcionalitou
- Automatické předávání HTTP headers pro optimální přehrávání

### Bezpečnost

* 🔐 **API klíč autentifikace** - chráněný přístup k addonu
* 🛡️ **IP omezení** přes nginx reverse proxy
* 📊 **Detailní logování** pro monitoring přístupů

## 🏗️ Instalace a nasazení

### Požadavky

* Docker & Docker Compose
* SSL certifikát (Let's Encrypt doporučeno)
* Real-Debrid účet (volitelné)
* SKTorrent.eu účet

### Krok 1: Příprava projektu

Klonování repozitáře:

```bash
git clone https://github.com/Martin22/SKTorrent-Hybrid-Stremio-Addon.git
cd SKTorrent-Hybrid-Stremio-Addon
```

Vytvoření SSL složky (pokud používáte vlastní certifikáty):

```bash
mkdir ssl
```

### Krok 2: Konfigurace .env souboru

Vytvořte `.env` soubor s následující konfigurací:

```env
# Real-Debrid konfigurace (volitelné)
REALDEBRID_API_KEY=your_real_debrid_api_key_here

# SKTorrent.eu přihlašovací údaje
SKT_UID=your_sktorrent_uid
SKT_PASS=your_sktorrent_pass_hash

# API klíč pro zabezpečení addonu (vygenerujte bezpečný klíč)
ADDON_API_KEY=skt_secure_api_key_123456789abcdef

# Režim zobrazování streamů
STREAM_MODE=BOTH

# Produkční nastavení
NODE_ENV=production
EXTERNAL_DOMAIN=your.domain.com
```

### Krok 3: Generování API klíče

Vygenerování bezpečného API klíče:

```bash
openssl rand -hex 32
```

Nebo jednodušší varianta:

```bash
echo "skt_$(date +%s)_$(openssl rand -hex 16)"
```

### Krok 4: Získání SKTorrent.eu přihlašovacích údajů

1. **Přihlaste se na [SKTorrent.eu](https://sktorrent.eu)**
2. **Otevřete Developer Tools** (F12) → Network tab
3. **Načtěte libovolnou stránku** na sktorrent.eu
4. **Najděte cookie hodnoty:**
   * `uid` - vaše uživatelské ID
   * `pass` - hash vašeho hesla
5. **Zkopírujte hodnoty** do .env souboru

### Krok 5: Reverzní proxy a SSL certifikát

Pro bezpečný provoz je doporučeno provozovat addon za reverzní proxy s platným SSL certifikátem. Níže jsou ukázky konfigurace pro **nginx** i **Apache2**.

#### Doporučený způsob získání SSL certifikátu (acme.sh)

1. Instalace acme.sh:
   ```bash
   curl https://get.acme.sh | sh
   ~/.acme.sh/acme.sh --upgrade --auto-upgrade
   ```
2. Vytvoření certifikátu pro vaši doménu (např. s DNS ověřením):
   ```bash
   ~/.acme.sh/acme.sh --issue --standalone -d your-domain.com
   ~/.acme.sh/acme.sh --install-cert -d your-domain.com \
     --key-file       /cesta/k/ssl/key.pem \
     --fullchain-file /cesta/k/ssl/cert.pem
   ```
   Certifikáty pak použijte v konfiguraci proxy.

#### Nginx (doporučeno)

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    ssl_certificate /cesta/k/ssl/cert.pem;
    ssl_certificate_key /cesta/k/ssl/key.pem;

    # IP omezení (volitelné)
    # allow 85.160.123.456;
    # deny all;

    location / {
        proxy_pass http://127.0.0.1:7000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

#### Apache2 (alternativa)

```apache
<VirtualHost *:443>
    ServerName your-domain.com
    SSLEngine on
    SSLCertificateFile /cesta/k/ssl/cert.pem
    SSLCertificateKeyFile /cesta/k/ssl/key.pem
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:7000/
    ProxyPassReverse / http://127.0.0.1:7000/
    # IP omezení (volitelné)
    # <RequireAny>
    #   Require ip 85.160.123.456
    #   Require ip 192.168.1.0/24
    # </RequireAny>
</VirtualHost>
```

> **Poznámka:** Pokud změníte kód nebo závislosti, použijte `docker-compose up --build -d`.

### Krok 6: Spuštění služeb

```bash
docker-compose up --build -d
```

Sledování logů:

```bash
docker-compose logs -f sktorrent-hybrid
```

Kontrola stavu služeb:

```bash
docker-compose ps
```

### Krok 7: Instalace do Stremio

1. **Přejděte na informační stránku:** `https://your-domain.com`
2. **Zkopírujte manifest URL s API klíčem:**

```
https://your-domain.com/manifest.json?api_key=your_generated_api_key
```

3. **V Stremio přejděte na:** Addons → Community Addons
4. **Vložte URL s API klíčem** a klikněte Install

## ⚙️ Konfigurace

### Módy streamování (STREAM_MODE)

#### `RD_ONLY` - Pouze Real-Debrid (Doporučeno)

```env
STREAM_MODE=RD_ONLY
```

* ✅ Zobrazuje pouze ⚡ Real-Debrid streamy
* ✅ Čistý interface bez duplicity
* ✅ Optimální pro uživatele s Real-Debrid

#### `BOTH` - Real-Debrid + Torrent streamy

```env
STREAM_MODE=BOTH
```

* ✅ Zobrazuje ⚡ Real-Debrid i 🎬 torrent streamy
* ✅ Maximální flexibilita výběru
* ❌ Více možností může být matoucí

#### `TORRENT_ONLY` - Pouze torrenty

```env
STREAM_MODE=TORRENT_ONLY
```

* ✅ Pouze 🎬 torrent streamy ze sktorrent.eu
* ✅ Rychlejší odezva (bez RD API volání)
* ✅ Funguje bez Real-Debrid účtu

### Real-Debrid API klíč

1. **Přihlaste se na [Real-Debrid.com](https://real-debrid.com)**
2. **Přejděte na:** Account → API → Generate
3. **Zkopírujte API klíč** do .env souboru

## 🛡️ Bezpečnost

### API klíč autentifikace

Addon je chráněn API klíčem, který musí být součástí všech požadavků:

* Manifest URL: `https://domain.com/manifest.json?api_key=YOUR_KEY`
* Automatické předávání klíče v stream požadavcích

### IP omezení

Konfigurace nginx umožňuje omezit přístup pouze na povolené IP adresy.

### HTTPS a SSL

Všechna komunikace je šifrovaná pomocí SSL/TLS certifikátů.

## 📊 Monitoring a údržba

### Sledování logů

```bash
docker-compose logs -f sktorrent-hybrid
docker-compose logs -f nginx
docker-compose logs -f
```

### Restart služeb

```bash
docker-compose restart sktorrent-hybrid
```

```bash
docker-compose down && docker-compose up -d
```

Rebuild s novými změnami:

```bash
docker-compose up --build -d
```

### Aktualizace konfigurace

Po změně .env souboru:

```bash
docker-compose down
docker-compose up -d
```

Po změně kódu:

```bash
docker-compose up --build -d
```

## 🔧 Řešení problémů

### Časté problémy

**Pomalé načítání videí:**
* Proxy streaming vyžaduje více bandwidth a CPU
* Video data prochází přes váš server místo přímého připojení
* Zvažte upgrade serveru při častém používání

**Addon se nenačte:**

* Zkontrolujte API klíč v URL
* Ověřte, že je vaše IP adresa povolená v nginx
* Zkontrolujte SSL certifikáty

**Real-Debrid nefunguje:**

* Ověřte platnost RD API klíče
* Zkontrolujte logy:

```bash
docker-compose logs sktorrent-hybrid
```

**Torrenty se nehledají:**

* Zkontrolujte SKT_UID a SKT_PASS v .env
* Ověřte připojení k sktorrent.eu

### Debug informace

Test připojení k addonu:

```bash
curl https://your-domain.com/manifest.json?api_key=YOUR_KEY
```

Test nginx konfigurace:

```bash
nginx -t
```

Kontrola Docker kontejnerů:

```bash
docker-compose ps
```

## 📋 Struktura projektu

```
sktorrent-hybrid-stremio-addon/
├── sktorrent-addon.js          # Hlavní addon (vstupní bod)
├── base-url-manager.js         # Správa veřejné domény
├── config.js                   # Centrální konfigurace
├── auth.js                     # Autentizace a session management
├── realdebrid.js               # Real-Debrid API helper
├── streaming.js                # Správa streamování a proxy
├── torrent-search.js           # Vyhledávání a zpracování torrentů
├── templates.js                # Generování HTML šablon
├── utils.js                    # Pomocné funkce
├── package.json                # NPM závislosti
├── Dockerfile                  # Docker image konfigurace
├── docker-compose.yaml         # Docker Compose orchestrace
├── LICENSE                     # Licence
├── README.md                   # Tento soubor
└── sktorrent-addon-logo.png    # Logo addonu
```

## 🤝 Přispívání

Příspěvky jsou vítány! Pokud najdete chybu nebo máte návrh na vylepšení:

1. Vytvořte Issue s popisem problému
2. Forkněte repozitář a vytvořte feature branch
3. Vytvořte Pull Request s popisem změn

## ⚠️ Právní upozornění

**Tento addon je určen výhradně pro osobní, vývojové a experimentální účely.**

* Používání tohoto addonu je **na vlastní riziko**
* Autor nenese **žádnou zodpovědnost** za porušení autorských práv
* Projekt **nepropaguje pirátství**, ale demonstruje technické možnosti
* **Respektujte autorská práva** a místní právní předpisy

## 📄 Licence

MIT License - volné použití bez záruky

## 👨‍💻 Autoři

* **Původní autor:** [SKTorrent Stremio Addon](https://github.com/JohnnyK007/Sktorrent-Stremio-addon)
* **Hybrid verze:** Rozšíření o Real-Debrid funkcionalitu a pokročilé zabezpečení

---

**🌟 Pokud vám tento addon pomohl, zvažte hvězdičku na GitHubu!**
