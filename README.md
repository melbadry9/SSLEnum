# SSLEnum
Reconnaissance using SSL certificate Alt Names and Organization - Dangling DNS records - 

## Install

```bash
pip3 install -r requirements.txt
```


## Usage

- Help 

```txt
usage: sslenum.py [-h] -l LIST [-t THREADS] [-dom | -org | -cn | -dns]

optional arguments:
  -h, --help            show this help message and exit
  -l LIST, --list LIST
  -t THREADS, --threads THREADS
  -dom, --domain
  -org, --organization
  -cn, --common_name
  -dns, --dangling_dns
  ```

- Search for Alt Names

```bash
python3 sslenum.py -l list.txt -t 10 -dom
```

- Grab Orgnization Names

```bash
python3 sslenum.py -l list.txt -t 10 -org
```

- Check for mismatched SSL certificate data compared to a hostname

```bash
python3 sslenum.py -l list.txt -t 10 -dns
```
