## gpg-fingerprint-filter-gpu

Generate an OpenPGP key whose fingerprint matches a specific pattern.

Get your lucky key! CUDA powered, so fast!

```
$ ./gpg-fingerprint-filter-gpu --help
  gpg-fingerprint-filter-gpu [OPTIONS] <pattern> <output>

  <pattern>                   Key pattern to match, for example 'X{8}|(AB){4}'
  <output>                    Save secret key to this path
  -a, --algorithm <ALGO>      PGP key algorithm [default: default]
  -t, --time-offset <N>       Max key timestamp offset [default: 15552000]
  -w, --thread-per-block <N>  CUDA thread number per block [default: 512]
  -h, --help
```

### Pattern

- Only matches end part of a string.
- A hex digit means itself.
- Other Latin alphabets (`g` to `z`) are to match any hex digit.
- `{N}` to repeat previous digit or group for N times.
- `(PATTERN)` a group pattern.
- Use `|` to split multiple patterns.

Examples:

- `deadbeef` equals to regex `deadbeef$`
- `x{8}` equals to regex `([0-9a-f])\1{7}$`
- `(xy){4}` equals to regex `([0-9a-f][0-9a-f])\1{3}$`
- `xxxxa{4}` equals to regex `([0-9a-f])\1{3}aaaa$`

### Import Key

Like this:

```
$ gpg --allow-non-selfsigned-uid --import private.pgp
```
