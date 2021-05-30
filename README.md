# SSLEnum

Reconnaissance using SSL certificate Alt Names and Organization - Dangling DNS records -

## Install

```bash
git clone https://github.com/melbadry9/SSLEnum.git
cd SSLEnum
cargo install --path .
```

## Usage

- Help

```txt
SSLEnum recon tool 0.1
Mohamed Elbadry <me@melbadry9.xyz>

USAGE:
    sslenum [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information      

OPTIONS:
    -d, --domain <DOMAIN>      Sets domain to check  
    -t, --threads <THREADS>    Sets number of threads
  ```

```bash
cat subdomains.list | sslenum -t 5 
````
