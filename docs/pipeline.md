# rmail — Pipeline de traitement des messages

Ce document décrit précisément ce qui se passe dans le code quand un mail arrive ou quand un mail est envoyé.

---

## 1. Réception d'un mail entrant

### 1.1 Acceptation de la connexion TCP

**Fichier :** `crates/server/src/smtp_listener.rs`

- Le serveur écoute sur les ports configurés (25, 587, 465).
- Un `Semaphore` (max 1024) limite les connexions simultanées.
- Port 465 → TLS immédiat (`tls.accept()` avant toute lecture).
- Ports 25/587 → connexion en clair, STARTTLS disponible en cours de session.

### 1.2 Session SMTP

**Fichier :** `crates/smtp/src/session.rs`

La machine à état `Session` traite les commandes ligne par ligne :

```
EHLO mail.expediteur.com
  → 250-rmail ... (capacités annoncées : STARTTLS, AUTH, SIZE)

STARTTLS                          ← optionnel sur port 25/587
  → 220 Go ahead
  [handshake TLS, session reprend sur flux chiffré]

MAIL FROM:<alice@expediteur.com>
  → 250 OK

RCPT TO:<bob@example.com>
  → 250 OK  (vérifie que le domaine est local et l'utilisateur existe)

DATA
  → 354 Start input
  [corps RFC 5322, ligne par ligne]
  .                               ← fin du message
  → Action::Enqueue déclenchée
```

### 1.3 Vérification auth (SPF / DKIM / DMARC)

**Fichier :** `crates/server/src/smtp_listener.rs` → `should_reject_inbound()`  
**Fichier :** `crates/auth/src/checker.rs` → `verify()`

Avant d'accepter le message en queue, si l'expéditeur n'est **pas** authentifié (`AUTH`) et que `MAIL FROM` n'est pas nul :

1. **SPF** : `resolver.verify_spf(client_ip, helo, server_hostname, mail_from)` via Cloudflare DNS.
2. **DKIM** : parse du message + `resolver.verify_dkim(&auth_msg)`.
3. **DMARC** : `resolver.verify_dmarc(...)` — applique la politique du domaine expéditeur.

Si DMARC dit `reject` → réponse `550 5.7.1` au client, message refusé.  
Sinon → on passe à l'étape suivante.

> Les soumissions authentifiées (port 587 + AUTH LOGIN) sautent ces vérifications.

### 1.4 Mise en queue

**Fichier :** `crates/queue/src/lib.rs` → `Queue::enqueue()`

Deux fichiers écrits dans `incoming/`, dans cet ordre :

1. `<id>.eml` — corps RFC 5322 brut, `fsync` des données.
2. `<id>.env` — enveloppe bincode-encodée (`Envelope`), `fsync` des données.

L'enveloppe est le **commit marker** : si le processus crashe entre les deux écritures, le fichier `.eml` orphelin est nettoyé au redémarrage par `Queue::recover()`. Le message ne peut pas être perdu une fois les deux fichiers écrits.

→ `250 2.0.0 OK queued as <id>` renvoyé au client.

---

## 2. Traitement de la queue (queue manager)

**Fichier :** `crates/server/src/queue_manager.rs`

Tourne en boucle toutes les **10 secondes** dans une Tokio task dédiée.

### Tick

```
incoming/ ──rename──→ active/      (promotion atomique)

Pour chaque message dans active/ :
  ├── tous destinataires locaux ?
  │     └── maildir.deliver() → new/    (livraison locale)
  └── destinataire(s) distant(s) ?
        └── delivery::deliver_message() (livraison distante, voir §3)

Si tous faits (livrés ou échec permanent) :
  ├── des échecs ? → bounce::generate() (voir §4)
  └── queue.remove() ← supprime active/

Si certains encore en attente :
  ├── budget épuisé (max_retries ou bounce_after_hours) ?
  │     └── marque tout en échec → bounce → remove
  └── sinon : calcule délai backoff exponentiel
              → next_retry_at = now + delay
              → active/ ──rename──→ deferred/

deferred/ : re-promeus en active/ ceux dont next_retry_at est passé.
```

**Backoff :** `initial_retry_secs × 2^retry_count`, plafonné à `max_retry_secs` (défaut : 300 s → 14 400 s max).

---

## 3. Envoi d'un mail sortant

**Fichier :** `crates/server/src/delivery.rs`

Appelé par le queue manager pour chaque message avec au moins un destinataire distant.

### 3.1 Signature DKIM

**Fichier :** `crates/auth/src/dkim.rs` → `sign()`

Si `MAIL FROM` appartient à un domaine hébergé localement :
- Lecture de la clé RSA privée (`domain.dkim_key`).
- Signature RSA-SHA256 des headers `From To Subject Date Message-ID MIME-Version Content-Type`.
- Préfixe `DKIM-Signature:` ajouté au corps.

### 3.2 Résolution MX

**Fichier :** `crates/dns/src/lib.rs` → `Resolver::mx()` + `Resolver::host()`

- Les destinataires sont regroupés par domaine.
- Pour chaque domaine : lookup MX → tri par priorité → lookup A/AAAA pour chaque MX.
- Résultat : liste de `(SocketAddr, hostname)` en ordre de priorité croissante.

> Le resolver utilise **exclusivement Cloudflare DNS** (1.1.1.1 / 1.0.0.1), jamais `/etc/resolv.conf`.

### 3.3 Connexion SMTP sortante

**Fichier :** `crates/smtp/src/client.rs` → `client::deliver()`

Pour chaque MX cible (dans l'ordre) :

```
Connexion TCP port 25
← 220 banner
→ EHLO <server.hostname>
← 250 (capacités)

Si STARTTLS annoncé :
  → STARTTLS
  [handshake TLS]

→ MAIL FROM:<expéditeur>
→ RCPT TO:<destinataire> [pour chaque adresse du domaine]
→ DATA
→ [corps signé DKIM]
→ .
← 250 OK
```

- Succès → `envelope.mark_delivered(addr)` pour chaque destinataire accepté.
- Erreur permanente (5xx) → `envelope.mark_failed(...)`.
- Erreur transitoire (4xx / réseau) → on essaie le MX suivant ; si aucun ne fonctionne, le message reste en queue pour retry.

---

## 4. Bounce (DSN)

**Fichier :** `crates/server/src/bounce.rs`

Déclenché quand un message ne peut pas être livré (échec permanent ou budget de retry épuisé).

- Si `MAIL FROM` est nul (`<>`) → **aucun bounce** (RFC 5321 : on ne génère pas de bounce sur un bounce).
- Sinon : génère un corps DSN au format texte (expéditeur `MAILER-DAEMON@hostname`), l'enqueue comme nouveau message vers l'expéditeur original.

---

## 5. Livraison locale (Maildir)

**Fichier :** `crates/mailbox/src/lib.rs` → `Maildir::deliver()`

```
mailbox_dir/<domain>/<local>/
├── tmp/   ← écriture du fichier message (fsync)
└── new/   ← rename atomique depuis tmp/
```

Le fichier est nommé `<timestamp>.<pid>.<hostname>` (format Maildir standard). Lock-free par construction.

---

## 6. Lecture IMAP

**Fichier :** `crates/server/src/imap_listener.rs` + `crates/imap/src/session.rs`

- Écoute sur les ports 143 (STARTTLS disponible) et 993 (TLS implicite).
- Semaphore identique (max 1024 connexions simultanées).
- Machine à état IMAP4rev2 : `Not Authenticated → Authenticated → Selected`.
- Lit depuis `cur/` (messages vus) et `new/` (messages non vus) du Maildir de l'utilisateur.
- `EXPUNGE` → suppression physique du fichier.
- `COPY` / `MOVE` → copie ou rename entre dossiers Maildir.

---

## Résumé visuel

```
Internet
   │
   ▼
[smtp_listener] ←─ TCP 25/587/465 ─── max 1024 connexions (Semaphore)
   │  Session SMTP (smtp::Session)
   │  STARTTLS si port 25/587
   │  SPF + DKIM + DMARC (checker::verify) ← Cloudflare DNS
   │
   ▼
[queue/incoming]  <id>.eml + <id>.env  (fsync, crash-safe)
   │
   ▼  (toutes les 10 s)
[queue_manager]
   ├──► local  → [mailbox::deliver] → Maildir new/   ←── [imap_listener]
   └──► remote → [delivery]
                   DKIM sign
                   MX lookup (Cloudflare DNS)
                   SMTP client → MX cible port 25
                   └── échec transitoire → deferred/ (backoff exponentiel)
                   └── échec permanent  → bounce::generate() → queue/incoming
```
