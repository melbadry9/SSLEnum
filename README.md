# SSLEnum

Reconnaissance using SSL certificate Alt Names and Organization - Dangling DNS records -

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

## Usage

- Help

```txt
SSLEnum [SSL Data Enumeration] 0.2.1
Mohamed Elbadry <me@melbadry9.xyz>

USAGE:
    sslenum [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --domain <DOMAIN>      Sets domain to check
    -p, --port <PORT>          Sets port number [default: 443]
    -t, --threads <THREADS>    Sets number of threads [default: 5]
  ```

```bash
cat subdomains.list | sslenum -t 5 -p 443
````
