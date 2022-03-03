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

Import the generated private key:

```
$ gpg --allow-non-selfsigned-uid --import private.pgp
```

The private key file doesn't have a self-signed UID on it. GPG will display `NONAME` as the default UID.
You need to add a valid UID and remove the default one to make the key usable:

```
$ gpg --edit-key <KEY_FINGERPRINT>
gpg> adduid
Real name: Your Name Here
Email address: your_email@example.com
......
gpg> uid 1
gpg> deluid
gpg> save
```
