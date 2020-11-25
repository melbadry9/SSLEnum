# SSLEnum
Reconnaissance using SSL certificate Alt Names and Organization

## Install

```bash
pip3 install -r requirements.txt
```


## Usage

- Help 

```txt
usage: sslenum.py [-h] -l LIST [-t THREADS] [-d | -o]

optional arguments:
  -h, --help            show this help message and exit
  -l LIST, --list LIST
  -t THREADS, --threads THREADS
  -d, --domain
  -o, --organization
  ```

- Search for Alt Names

```bash
python3 sslenum.py -l list.txt -t 10 -d
```

- Grab Orgnization Names

```bash
python3 sslenum.py -l list.txt -t 10 -o
```