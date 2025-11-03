#!/usr/bin/env python

import sys
import ssl
import json
import socket
import OpenSSL
import argparse
import tldextract
import asyncio
from urllib3.contrib.pyopenssl import get_subj_alt_name

# async TLS fetch of peer certificate (returns OpenSSL.crypto.X509)
async def fetch_cert_x509(host: str, port: int, timeout: float):
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port, ssl=sslctx),
            timeout=timeout
        )
    except Exception:
        raise

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            raise RuntimeError("no ssl_object")
        der = ssl_obj.getpeercert(binary_form=True)
        if der is None:
            raise RuntimeError("no peer cert")
        # load ASN.1 DER cert into pyOpenSSL X509
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)
        return x509
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

def extract_alt_names(crt):
    try:
        parsed_alt = get_subj_alt_name(crt)
        return [dom[1] for dom in parsed_alt]
    except Exception:
        return []

def extract_org(crt):
    try:
        return crt.get_subject().O
    except Exception:
        return None

def extract_cn(crt):
    try:
        return crt.get_subject().CN
    except Exception:
        return None

async def grab_info_async(host: str, port: int, timeout: float):
    """
    Async wrapper that returns the same dict as previous grab_info,
    or None on failure.
    """
    try:
        crt = await fetch_cert_x509(host, port, timeout)
        org = extract_org(crt)
        cn = extract_cn(crt)
        domains = extract_alt_names(crt)
        return {"host": host, "org": org, "cn": cn, "alt_doms": domains}
    except (ConnectionRefusedError, ConnectionResetError, socket.error, asyncio.TimeoutError):
        return None
    except Exception:
        return None

def stdin_lines():
    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield line

def file_lines(path):
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line

def args():
    parser = argparse.ArgumentParser(description="Async SSL cert enumerator (streaming, low-memory)")
    parser.add_argument("-l","--list", type=str, required=False, help="Path to file with newline-separated hosts")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrency (number of worker coroutines)")
    parser.add_argument("--port", type=int, default=443, help="Port to connect to (default 443)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-host connect timeout in seconds")
    parser.add_argument("--output", type=str, default="output.json", help="Output file (newline-delimited JSON)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-dom","--domain", action="store_true", help="Print discovered SAN domains (streaming)")
    group.add_argument("-org","--organization", action="store_true", help="Print organization per host (streaming)")
    group.add_argument("-cn","--common_name", action="store_true", help="Print common name per host (streaming)")
    group.add_argument("-dns","--dangling_dns", action="store_true", help="Print hosts with dangling CNs (streaming)")
    return parser.parse_args()

async def producer(queue: asyncio.Queue, source_iter):
    for host in source_iter:
        await queue.put(host)
    # producer done

async def worker(name: int, queue: asyncio.Queue, out_queue: asyncio.Queue, port: int, timeout: float):
    while True:
        host = await queue.get()
        if host is None:
            queue.task_done()
            break
        try:
            result = await grab_info_async(host, port, timeout)
            if result:
                await out_queue.put(result)
        finally:
            queue.task_done()
    # worker exits

async def output_writer(out_queue: asyncio.Queue, out_path: str, options):
    # open file once (truncate), write newline-delimited JSON lines
    with open(out_path, "w", encoding="utf-8") as out_f:
        while True:
            item = await out_queue.get()
            if item is None:
                out_queue.task_done()
                break
            # print one-line JSON to stdout (default)
            line = json.dumps(item, ensure_ascii=False)
            print(line, flush=True)
            # write NDJSON line
            out_f.write(line + "\n")
            out_f.flush()
            # additional streaming outputs according to flags
            if options.domain:
                for d in item.get("alt_doms", []):
                    print(d, flush=True)
            if options.organization:
                org = item.get("org")
                if org:
                    print(f"{item['host']}: {org}", flush=True)
            if options.common_name:
                cn = item.get("cn")
                if cn:
                    print(f"{item['host']}: {cn}", flush=True)
            if options.dangling_dns:
                try:
                    host_rd = tldextract.extract(item['host']).top_domain_under_public_suffix
                    cn_rd = tldextract.extract(item['cn']).top_domain_under_public_suffix
                    if host_rd != cn_rd:
                        print(item['host'], flush=True)
                except Exception:
                    print(item.get('host'), flush=True)
            out_queue.task_done()

async def main_async():
    options = args()

    # determine input source (streaming generator)
    if not sys.stdin.isatty():
        src = stdin_lines()
    elif options.list:
        src = file_lines(options.list)
    else:
        print("No input provided: supply -l/--list or pipe hosts into stdin", file=sys.stderr)
        raise SystemExit(1)

    q_maxsize = max(4, options.threads * 4)
    queue = asyncio.Queue(maxsize=q_maxsize)
    out_queue = asyncio.Queue()

    # start writer
    writer_task = asyncio.create_task(output_writer(out_queue, options.output, options))

    # start workers
    workers = []
    for i in range(options.threads):
        w = asyncio.create_task(worker(i, queue, out_queue, options.port, options.timeout))
        workers.append(w)

    # run producer synchronously (it will await queue.put)
    prod_task = asyncio.create_task(producer(queue, src))

    # wait for producer to finish
    await prod_task
    # signal workers to stop
    for _ in workers:
        await queue.put(None)

    # wait until all queued items processed
    await queue.join()

    # wait for workers to finish
    await asyncio.gather(*workers, return_exceptions=True)

    # signal writer to finish and wait
    await out_queue.put(None)
    await out_queue.join()
    await writer_task

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()