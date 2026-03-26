# Watch: runtime/secret for Secure Key Erasure

**Status**: Waiting for stabilization (experimental in Go 1.26)

## Context

`connector.Close()` zeroes the encryption key manually, but Go's GC may copy
the backing array during heap compaction — prior copies cannot be zeroed.
This limitation is documented in `driver.go`.

## What runtime/secret Provides

The `runtime/secret` package (Go 1.26, experimental) offers secure erasure of
cryptographic temporaries from registers, stack, and heap. It would replace
the current best-effort zeroing with a proper guarantee.

## Current Limitations

- Requires `GOEXPERIMENT=runtimesecret` build tag
- Supported only on amd64/arm64 Linux
- API not yet stable

## Action

When `runtime/secret` exits experimental (likely Go 1.27 or 1.28):

1. Replace manual key zeroing in `connector.Close()` with `secret.Erase()` or equivalent
2. Consider wrapping the key allocation itself with `runtime/secret` facilities
3. Update the limitation comment in `driver.go`
4. Remove this TODO
