# Local development setup

This note documents the conventions for hacking on **neverlur** alongside its sibling repo **gjallarhorn** without dealing with `go.mod` replace directives or constantly running `go mod tidy`.

## Repository layout

Clone both repos as siblings under one directory:

```text
~/projects/                          (or wherever)
├── neverlur/                        (this repo)
└── gjallarhorn/                     (https://github.com/oluies/gjallarhorn)
```

## Go workspace

Create a `go.work` file at the parent directory:

```text
// ~/projects/go.work
go 1.25

use (
    ./neverlur
    ./gjallarhorn
)
```

With this file present, any `go build` / `go test` run from inside either repo resolves `github.com/oluies/neverlur` and `github.com/oluies/gjallarhorn` imports to the **local working copy** instead of the version pinned in the consumer's `go.mod`. Live edits to either tree are picked up immediately. No replace directives, no `go mod tidy` after every cross-repo edit.

`go.work` and `go.work.sum` are `.gitignore`'d in both repos — this is per-developer local config. Do not commit it.

## Why not `replace` directives?

`replace github.com/oluies/gjallarhorn => ../gjallarhorn` in `go.mod` works for the same purpose but has to be **removed before tagging a release**. The workspace approach keeps the published module manifests clean; nothing in this repo's `go.mod` ever references a local path.

## Constitution note

The constitution (`.specify/memory/constitution.md`, §"Compatibility and Coordination") requires that changes crossing the `neverlur` ↔ `gjallarhorn` boundary land as **paired pull requests** referencing each other. The workspace setup makes paired development convenient locally but does not change the paired-PR requirement on the remote side. Module paths (`github.com/oluies/neverlur`, `github.com/oluies/gjallarhorn`) remain canonical and stable.

## Verifying the workspace is active

```sh
$ go env GOWORK
/Users/<you>/projects/go.work
```

If `GOWORK` is empty, either you're not inside a workspace tree or `go.work` is missing.
