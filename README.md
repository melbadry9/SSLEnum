# SSLEnum

Extract SSL certificate data (Subject Name, Subject Alt Names, Organisation)

## Install

- Install from `crates.io`
```bash
cargo install sslenum --force 
```

- Intall from `github`
```bash
git clone https://github.com/melbadry9/SSLEnum.git
cd SSLEnum
cargo install --path .
```

## Usagec

- Help

```txt
SSLEnum [SSL Data Enumeration] 2.0.0
Mohamed Elbadry

USAGE:
    sslenum [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --domain <DOMAIN>      Single domain to test
    -o, --out <FILE>           Write results to JSONL file
    -p, --port <PORT>           [default: 443]
    -t, --threads <THREADS>    Concurrent blocking probes [default: 200]
    -T, --timeout <SECS>       Per-IP connect/read/write timeout in seconds [default: 1]
```

```bash
$ cat subdomains.list | sslenum -t 50 -p 443 -T 3 -o ssl.json
$ sslenum -d example.com | jq
````

- Output

```json
{
  "hostname": "example.com",
  "ip": "23.215.0.138",
  "org": [
    "Internet Corporation for Assigned Names and Numbers"
  ],
  "cn": [
    "*.example.com"
  ],
  "alt_names": [
    "*.example.com",
    "example.com"
  ],
  "dangling": false
}
```
