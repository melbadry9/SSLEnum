import sys
import argparse
import tldextract
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.contrib import pyopenssl as reqs


def read_crt(host,port):
    x509 = reqs.OpenSSL.crypto.load_certificate(
        reqs.OpenSSL.crypto.FILETYPE_PEM,
        reqs.ssl.get_server_certificate((host, port))
    )
    return x509

def extract_alt_names(crt):
    parsed_alt = reqs.get_subj_alt_name(crt)
    domains = [ tldextract.extract(dom[1]).registered_domain for dom in parsed_alt ]
    return set(domains)

def extract_org(crt):
    return crt.get_subject().O

def grab_info(host, port=443):
    try:
        crt = read_crt(host, port)
        org = extract_org(crt)
        domains = extract_alt_names(crt)
        return {"host": host, "org": org, "alt_doms": domains}
    except Exception as e:
        pass

def read_file(file):
    with open(file, "r", encoding="utf-8") as e:
        domains = [ dom.rstrip() for dom in e.read().splitlines() ]
        return domains

def args():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-l","--list", type=str, required=True,)
    parser.add_argument("-t", "--threads", type=int, default=10)
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d","--domain", action="store_true")
    group.add_argument("-o","--organization", action="store_true")
    return parser.parse_args()

def mass_info():
    options = args()
    found_domains = set()
    domains = read_file(options.list)
    Process = ThreadPoolExecutor(max_workers=options.threads)
    results = Process.map(grab_info, domains)
    Process.shutdown(wait=True)
    if options.domain:
        for re in results: 
            try:
                found_domains = found_domains.union(re['alt_doms'])
            except:
                pass
        for i in found_domains:
            print(i)
    if options.organization:
        for re in results:
            try:
                print("{0}: {1}".format(re['host'], re['org']))
            except:
                pass
    
if __name__ == '__main__':
    mass_info()