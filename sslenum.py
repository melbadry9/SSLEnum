import sys
import ssl
import json
import OpenSSL
import argparse
#import tldextract
from concurrent.futures import ThreadPoolExecutor
from urllib3.contrib.pyopenssl import get_subj_alt_name


def read_crt(host,port):
    x509 = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        ssl.get_server_certificate((host, port))
    )
    return x509

def extract_alt_names(crt):
    parsed_alt = get_subj_alt_name(crt)
    #domains = [ tldextract.extract(dom[1]).registered_domain for dom in parsed_alt ]
    domains = [ dom[1] for dom in parsed_alt ]
    return domains

def extract_org(crt):
    return crt.get_subject().O

def extract_cn(crt):
    return crt.get_subject().CN

def grab_info(host, port=443):
    try:
        crt = read_crt(host, port)
        org = extract_org(crt)
        cn = extract_cn(crt)
        domains = extract_alt_names(crt)
        return {"host": host, "org": org, "cn": cn, "alt_doms": domains}
    except Exception as e:
        print(e)

def read_file(file):
    with open(file, "r", encoding="utf-8") as e:
        domains = [ dom.rstrip() for dom in e.read().splitlines() ]
        return domains

def args():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-l","--list", type=str, required=True,)
    parser.add_argument("-t", "--threads", type=int, default=10)
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-dom","--domain", action="store_true")
    group.add_argument("-org","--organization", action="store_true")
    group.add_argument("-cn","--common_name", action="store_true")
    return parser.parse_args()

def mass_info():
    log_data = []
    options = args()
    found_domains = set()
    domains = read_file(options.list)
    Process = ThreadPoolExecutor(max_workers=options.threads)
    results = Process.map(grab_info, domains)
    Process.shutdown(wait=True)
    
    for re in results:
        print(re)
        log_data.append(re)

    if options.domain:
        for re in log_data: 
            try:
                found_domains = found_domains.union(re['alt_doms'])
            except KeyError:
                pass
        for i in found_domains:
            print(i)
    
    if options.organization:
        for re in log_data:
            try:
                print("{0}: {1}".format(re['host'], re['org']))
            except KeyError:
                pass
    
    if options.common_name:
        for re in log_data:
            try:
                print("{0}: {1}".format(re['host'], re['cn']))
            except KeyError:
                pass

    with open("log.json", "w", encoding="utf-8") as log:
        log.write(json.dumps(log_data, indent=4))
    
if __name__ == '__main__':
    mass_info()