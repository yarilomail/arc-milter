# arc-milter

Postfix **milter** in Go that adds an ARC set ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) to each forwarded message, sealed with the forwarder's own key. One process, one job: it checks the chain the message arrived with, copies the forwarding ADMD's `Authentication-Results`, signs the message and seals the chain. The key is a row of the same `dkim` table as dkim-milter's, encrypted with a Vault Transit key of its own, `arc`.

Licensed under **AGPLv3**, see [LICENSE](LICENSE). **Website:** [yarilomail.org](https://yarilomail.org) · **Docs:** [doc.yarilomail.org](https://doc.yarilomail.org)

[![CI](https://github.com/yarilomail/arc-milter/actions/workflows/ci.yaml/badge.svg?branch=develop)](https://github.com/yarilomail/arc-milter/actions/workflows/ci.yaml) [![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](app/go/go.mod) [![Container](https://img.shields.io/badge/ghcr.io-arc--milter-blue?logo=github)](https://github.com/yarilomail/arc-milter/pkgs/container/arc-milter) [![Docker Hub](https://img.shields.io/docker/pulls/0kaba0/arc-milter?logo=docker&logoColor=white)](https://hub.docker.com/r/0kaba0/arc-milter) [![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE) ![Status: development](https://img.shields.io/badge/status-development-orange)

## Where it runs

On the forwarding relay's outbound hop (yarilo-postfix's `relay-fwd-out`), after the forwarder's DKIM signer, so the ARC-Message-Signature covers the forwarder's `DKIM-Signature`. A receiver with a strict DMARC policy for the author's domain sees SPF and the author's DKIM broken by the forward; the ARC chain tells it what the forwarder saw when the message arrived.

The MX does not seal. It only needs a clean `Authentication-Results` with this ADMD's authserv-id (rspamd removes the ones that claim it from outside), and arc-milter copies that one.

## How it seals

For each message, at the end of its headers:

1. It collects the ARC sets the message came with. When the newest `ARC-Seal` says `cv=fail`, the chain ended at that hop (RFC 8617 5.1 step 2): nothing is added. The new instance is one above the highest `i=` any ARC field names, read past a broken field too, so it never repeats a number already there; at 50 nothing is added (4.2.1).
2. It reads the key (below). A message that will not be sealed is accepted here, and Postfix sends this milter no body for it.

At the end of the message:

3. It validates the chain (5.2): sets 1..n, each with exactly one `ARC-Authentication-Results`, `ARC-Message-Signature` and `ARC-Seal`; the newest AMS against the body and fields; every AS from n down to 1, with `cv=none` on the first and `cv=pass` on the others. A key under 1024 bits fails its signature (RFC 8301). The result is this hop's `cv`: `none` without a chain, `pass`, or `fail`.
4. It adds instance n+1 on top of the header, in this order from the top: `ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`.
   - The AAR is `i=n+1;` and the first `Authentication-Results` whose authserv-id is `AUTHSERV_ID`, copied as it stands. Without one it says `<authserv-id>; none`.
   - The AMS is `rsa-sha256`, `relaxed/relaxed`, over `From` (once more than it appears, so a `From` added later breaks it), `Reply-To`, `Subject`, `Date`, `To`, `Cc`, `Message-ID`, `In-Reply-To`, `References`, `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding`, `List-Id`, `List-Unsubscribe`, `List-Unsubscribe-Post` and `DKIM-Signature`, each as many times as the message has it.
   - The AS is `rsa-sha256` with this hop's `cv`. A chain this hop found broken is sealed `cv=fail`, and that seal signs only its own set, as if it were the only one (5.1.2).

The body is streamed through the hashes as it arrives and never held.

### When it cannot

| Case | What happens |
|:---|:---|
| The key was read before; the database or Vault is down now | sealed with the cached key |
| The key was never read; the database or Vault is down | tempfail at the end of the headers: the relay keeps the message and retries |
| The database answers and has no row for `SEAL_DOMAIN` with `ARC_SELECTOR` | accepted unsealed, one log line and `arc_messages_total{result="no_key"}`: that is configuration, not an outage |
| A key lookup in DNS fails for any reason but a name that does not exist (a timeout, SERVFAIL) | tempfail at the end of the message. A `cv=fail` seal over a lookup that may answer in a minute would spoil the chain for good |
| The same key name has kept failing so for `DNS_TEMPFAIL_GRACE_SECONDS` (4 hours) since its first failure | that signature counts as failed (RFC 8617 5.2.1 allows it) and the message is sealed `cv=fail`, instead of waiting in the queue to the end of its life when it would go out without this milter. Any answer from DNS clears the name. `DNS_FAILURE_STORE` says where the first failure is kept: `memory` (the default) in the process, so a restart or another replica starts the count again and the cv=fail seal comes up to one grace later; `redis` at `<REDIS_KEY_PREFIX>dnsfail:<name>`, shared by the replicas and kept over restarts, with a TTL of the grace plus a day renewed on each failure. Redis is called on its own 300 ms timeout, never on the message's spent deadline; the delete after a good answer goes in the background, at most once per name every 5 minutes. When Redis does not answer, it is left alone for 30 s and the count goes on in the process (`arc_redis_errors_total`), so an outage costs a message at most one 300 ms wait |
| The newest AMS uses `simple` header canonicalization and does not check | accepted unsealed, `arc_messages_total{result="simple_unverifiable"}`: the MTA hands the milter fields without the whitespace after the colon, so the signed bytes may not be the rebuilt ones, and a `cv=fail` on a sound chain could not be undone after |
| A key name does not exist, or the key is revoked (`p=` empty) | that signature fails, and the chain with it |

Every key lookup of one message shares one deadline, `DNS_TIMEOUT_SECONDS`: slow lookups cannot hold a message once per signature.

## Key

ARC defines `rsa-sha256` only, so the key is RSA. It is a row of its own in the `dkim` table: `domain` is the forwarder's domain (the same `fwd.<domain>` dkim-milter-fwd signs with and the SRS rewriting uses), `selector` is `ARC_SELECTOR` (`arc`). Rotating or revoking it never touches the forwarder's DKIM key, and a verifier sees by the selector which signature made what. The key query reads only that selector's row. The selector is `arc` or `arc-<label>`, and a rotation takes a new one (`arc-2027`) while the old key stays in DNS for a while: dkim-milter leaves exactly these selectors out of its own key query, so a DKIM selector may not be named so.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out arc.key
openssl pkey -in arc.key -pubout -outform DER | base64 -w0 > arc.pub
vault write -field=ciphertext transit/encrypt/arc plaintext="$(base64 -w0 < arc.key)" > arc.enc
```

```sql
INSERT INTO dkim (domain, selector, public_key, private_key_enc)
VALUES ('fwd.example.org', 'arc', '<arc.pub>', '<arc.enc>');
```

DNS: `arc._domainkey.fwd.example.org. TXT "v=DKIM1; k=rsa; p=<arc.pub>"`. Delete `arc.key` once the row is in.

The key cache, the Vault client and readiness are dkim-milter's: the key loads on the first message into an LRU cache, a key past `KEY_CACHE_TTL_SECONDS` seals on while its row is read again in the background, and `/readyz` answers 200 once the key query has run and, with Vault, the token may decrypt. One key per forwarding domain: the cache holds a handful.

The Vault role `arc-milter` binds this release's ServiceAccount (`arc-milter`) to a policy with `update` on `transit/decrypt/arc` and nothing else. The Transit key `dkim` decrypts every client domain's DKIM key, and this milter parses other servers' headers and DNS answers: a flaw in it must not reach those keys, so it never shares dkim-milter's key or role.

## Postfix

On the forwarding relay's outbound hop:

```
smtpd_milters = inet:dkim-milter-fwd:8891, inet:arc-milter:8893
milter_default_action = tempfail
```

The milter protocol version 2 this milter speaks has Postfix drop the space after a field's colon; arc-milter puts the usual one back, so a `simple`-canonicalized AMS from an earlier hop checks on the original bytes as long as that hop wrote one space.

## Environment

| Variable | Default | What |
|:---|:---|:---|
| `SEAL_DOMAIN` | --- (required) | `d=` of every seal, and the key row's domain |
| `ARC_SELECTOR` | `arc` | `s=`, and the key row's selector: `arc` or `arc-<label>` (`arc-2027` after a rotation), the selectors dkim-milter leaves out of its key query; any other is refused at start |
| `AUTHSERV_ID` | --- (required) | the authserv-id of this ADMD's `Authentication-Results`, copied into the AAR |
| `DNS_TIMEOUT_SECONDS` | `10` | one deadline for the key lookups of a message |
| `DNS_TEMPFAIL_GRACE_SECONDS` | `14400` | how long a key name may keep failing temporarily before its signature counts as failed |
| `DNS_FAILURE_STORE` | `memory` | `memory` or `redis`: where the first DNS failure of each key name is kept |
| `REDIS_ADDR` or `REDIS_SENTINEL_ADDRS` + `REDIS_SENTINEL_MASTER` | --- (one required with `redis`) | where the first DNS failures are kept; Sentinels comma-separated, with `REDIS_SENTINEL_USERNAME` / `REDIS_SENTINEL_PASSWORD` |
| `REDIS_USERNAME`, `REDIS_PASSWORD`, `REDIS_DB` | ---, ---, `0` | Redis login and database |
| `REDIS_KEY_PREFIX` | --- (required with `redis`; the chart sets `arc-milter:`) | so two installations on one Redis never share a key |
| `LISTEN_ADDR` | `0.0.0.0:8893` | milter listener |
| `METRICS_ADDR` | `0.0.0.0:8081` | `/healthz`, `/readyz`, `/metrics` |
| `MILTER_READ_TIMEOUT_SECONDS` / `MILTER_WRITE_TIMEOUT_SECONDS` | `3600` / `60` | a silent connection is closed after the first; a reply Postfix does not take after the second |
| `DB_DRIVER` | `postgres` | `postgres` or `mysql` |
| `DB_DSN` | --- (required) | database DSN |
| `DB_MAX_OPEN_CONNS` | `4` | connection pool |
| `ARC_SQL_QUERY` | the driver's default | the key row: `domain, selector, private_key_enc`, with two placeholders, the domain and the selector |
| `KEY_DECRYPT` | `vault` | `vault` (the column holds Transit ciphertext) or `none` (PEM) |
| `KEY_CACHE_SIZE` / `KEY_CACHE_TTL_SECONDS` / `KEY_CACHE_MISS_TTL_SECONDS` | `100` / `600` / `60` | the key cache |
| `VAULT_ADDR`, `VAULT_ROLE` | --- | required with `vault` |
| `VAULT_AUTH_PATH`, `VAULT_TRANSIT_PATH`, `VAULT_TRANSIT_KEY` | `kubernetes`, `transit`, `arc` | mounts and key; the key is this milter's own, never dkim-milter's `dkim` |
| `VAULT_CACERT` | --- | CA file for Vault's certificate |
| `VAULT_SA_TOKEN_FILE` | the pod's token | ServiceAccount token for Kubernetes auth |
| `LOG_LEVEL` | `info` | `debug` |

## Metrics

| Metric | What |
|:---|:---|
| `arc_messages_total{result}` | `sealed`, `chain_failed` (the newest seal says `cv=fail`), `instance_limit`, `simple_unverifiable`, `no_key`, `tempfail_key`, `tempfail_dns`, `error` |
| `arc_chain_total{cv}` | sealed messages by the `cv` this hop found: `none`, `pass`, `fail` |
| `arc_dns_temporary_errors_total` | key lookups that failed for a reason other than a missing name |
| `arc_dns_given_up_total` | of those, the ones taken as failed past `DNS_TEMPFAIL_GRACE_SECONDS` |
| `arc_redis_errors_total` | Redis calls that failed; the count went on in the process meanwhile |
| `arc_keys_loaded`, `arc_key_cache_lookups_total{result}`, `arc_key_fetch_errors_total{stage}` | the key cache, as dkim-milter's |

## Helm

`helm/`: a Deployment, Service, ServiceAccount, an optional NetworkPolicy (the milter port only from the Postfix pods) and an optional cert-manager Certificate for Vault's CA, all named after the release. Every variable above has its value; `sealDomain` and `authservId` are required. The chart's defaults are the code's; a test holds them equal.

## Build and release

`app/go`, Go 1.27. `go test ./...` covers canonicalization, chain validation against chains sealed by dkimpy (an independent implementation, [testdata/gen_dkimpy.py](app/go/testdata/gen_dkimpy.py)), a broken structure, a seal on a chain and a first seal, a broken chain sealed over its own set only, a chain that ended in `cv=fail`, the instance limit, the key cache and its outages, temporary and permanent DNS failures with one deadline per message, the chart's defaults, and full milter conversations. The seal on a dkimpy chain also validates with dkimpy (`ARC_DKIMPY_OUT` keeps that message).

Work lands on `develop` through pull requests; `main` takes releases only, with Lint and Test green. `develop` carries `-dev.N` in `helm/Chart.yaml`; each merge builds the image in GHCR. A merge into `main` with a release version builds `latest` and `<version>` in GHCR and on Docker Hub (`docker.io/0kaba0/arc-milter`) and creates the release `v<version>`.
