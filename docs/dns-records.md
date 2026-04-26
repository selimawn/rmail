# DNS records for a mail server

Everything a domain needs to send and receive mail reliably. `rmailctl domain dns <n>` generates these from the current config.

## Required

### MX — where mail for the domain goes

```
example.com.       IN  MX  10  mail.example.com.
```

The number (`10`) is the priority. Lower = preferred. With a single server, anything works.

### A / AAAA — IP of the mail server

```
mail.example.com.  IN  A     1.2.3.4
mail.example.com.  IN  AAAA  2001:db8::1
```

### PTR (reverse DNS) — IP → hostname

```
4.3.2.1.in-addr.arpa.  IN  PTR  mail.example.com.
```

Set on **the hosting provider** side, not in the domain's zone. Gmail / Outlook reject mail from servers without a matching PTR.

## Anti-spam (effectively required)

### SPF — who is allowed to send for this domain

```
example.com.  IN  TXT  "v=spf1 mx -all"
```

`mx` = the IPs listed in the MX records. `-all` = anything else is forged, hard fail.

### DKIM — cryptographic signature

```
rmail._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkq..."
```

`rmail` is the **selector** (configurable). The private key signs outgoing mail; the public key here lets receivers verify.

### DMARC — what to do when SPF/DKIM fail

```
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

`p=` is the policy: `none` (monitor), `quarantine` (spam folder), `reject` (drop). Start with `quarantine`, move to `reject` once reports look clean.

## Optional but recommended

### MTA-STS — force TLS for inbound

```
_mta-sts.example.com.  IN  TXT  "v=STSv1; id=20260426"
```

Plus an HTTPS file at `https://mta-sts.example.com/.well-known/mta-sts.txt`.

### TLS-RPT — get reports about TLS failures

```
_smtp._tls.example.com.  IN  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
```

### Autoconfig / Autodiscover — clients pick settings automatically

```
autoconfig.example.com.  IN  CNAME  mail.example.com.
_autodiscover._tcp.example.com.  IN  SRV  0 0 443 mail.example.com.
```

rmail v1 does not serve the autoconfig XML; can be added later.

## Minimum viable set

If you publish only these, mail works and gets delivered:

```
MX, A, PTR, SPF, DKIM, DMARC
```

The rest are quality-of-life and security hardening.
