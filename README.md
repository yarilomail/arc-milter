# arc-milter

Postfix **milter** in Go that adds an ARC set ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) to each forwarded message, sealed with the forwarder's own key. One process, one job: it checks the chain the message arrived with, copies the forwarding ADMD's `Authentication-Results`, signs the message and seals the chain. The key is a row of the same `dkim` table as dkim-milter's, encrypted with a Vault Transit key of its own, `arc`.

Licensed under **AGPLv3**, see [LICENSE](LICENSE). **Website:** [yarilomail.org](https://yarilomail.org) · **Docs:** [ARC sealing](https://doc.yarilomail.org/main/relay/arc_milter.html) on doc.yarilomail.org

[![CI](https://github.com/yarilomail/arc-milter/actions/workflows/ci.yaml/badge.svg?branch=develop)](https://github.com/yarilomail/arc-milter/actions/workflows/ci.yaml) [![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](app/go/go.mod) [![Container](https://img.shields.io/badge/ghcr.io-arc--milter-blue?logo=github)](https://github.com/yarilomail/arc-milter/pkgs/container/arc-milter) [![Docker Hub](https://img.shields.io/docker/pulls/0kaba0/arc-milter?logo=docker&logoColor=white)](https://hub.docker.com/r/0kaba0/arc-milter) [![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE) ![Status: stable](https://img.shields.io/badge/status-stable-brightgreen)

## What it does

- Seals mail the forwarding relay passes on to other domains (a Sieve `redirect`) with an ARC set: it validates the chain the message came with, copies the MX's `Authentication-Results`, signs the message and seals the chain, `rsa-sha256` only.
- Runs after the DKIM signer, so its signature covers the forwarder's `DKIM-Signature`.
- Keeps its key apart from the DKIM keys: an `arc` or `arc-<label>` row in the same `dkim` table, encrypted with a Vault Transit key and role of its own, so a flaw here cannot reach the client domains' DKIM keys.
- Never turns a doubt into a broken chain: a key it never read or a DNS lookup that may answer later delays the message, and only a name failing for hours counts as failed.

## Documentation

Everything about running it is on [doc.yarilomail.org](https://doc.yarilomail.org/main/relay/arc_milter.html):

- [Where it runs](https://doc.yarilomail.org/main/relay/arc_milter.html#where-it-runs), [sealing a message](https://doc.yarilomail.org/main/relay/arc_milter.html#sealing-a-message), [when it cannot seal](https://doc.yarilomail.org/main/relay/arc_milter.html#when-it-cannot-seal)
- [Keys](https://doc.yarilomail.org/main/relay/arc_milter.html#keys): the selectors, adding the key, rotation; [Vault Transit](https://doc.yarilomail.org/main/relay/arc_milter.html#vault-transit)
- [Postfix configuration](https://doc.yarilomail.org/main/relay/arc_milter.html#postfix-configuration), [readiness](https://doc.yarilomail.org/main/relay/arc_milter.html#readiness), [environment](https://doc.yarilomail.org/main/relay/arc_milter.html#environment), [Helm chart](https://doc.yarilomail.org/main/relay/arc_milter.html#helm-chart), [logs and metrics](https://doc.yarilomail.org/main/relay/arc_milter.html#logs-and-metrics)

## Repository

| Path | What |
|:---|:---|
| `app/go` | the milter, Go 1.27, `go test ./...` |
| `app/go/testdata` | ARC chains sealed by dkimpy, an independent implementation, and the script that makes them |
| `helm` | the chart |
| `helm_values` | values for the yarilo stand |

## Development and release

The tests check chain validation against the dkimpy chains, and a seal of this milter on one of them also validates with dkimpy (`ARC_DKIMPY_OUT` keeps that message for it).

Work lands on `develop` through pull requests, with Lint and Test green; `main` takes releases only. `develop` carries `-dev.N` in `helm/Chart.yaml`, bumped in the PR that changes the image, and each merge builds the image in GHCR. A merge into `main` with a release version publishes `<version>` and `latest` to GHCR and Docker Hub and creates the release `v<version>`.

A release keeps `main` inside `develop`: a pull request into `develop` sets the release version, a pull request from `develop` into `main` is merged with a merge commit (not squash or rebase), and the next pull request into `develop` starts the next `-dev.1`. No release branch, and no commit lands on `main` that `develop` does not have.
