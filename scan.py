#!/usr/bin/env python3

# @author Tilo-K

from pythonping import ping
import socket
import argparse
from threading import Thread
import progressbar
from termcolor import colored

MAX_THREADS = 50

def main():
    parser = argparse.ArgumentParser(description="A hand made tool to scan a Network")
    parser.add_argument('addresses', metavar='address',type=str, help='The address space to be scanned.')
    parser.add_argument('--ports', dest='ports', action='store_true')
    parser.set_defaults(ports=False)

    args = parser.parse_args()

    addresses = args.addresses
    port_scan = args.ports
    normal_scan(addresses, port_scan)


def normal_scan(addresses, port_scan):
    try:
        int(addresses.replace('.','').replace('*',''))
    except:
        addresses = socket.gethostbyname(addresses)
        
    addr_list = gen_addr([addresses])
    results = []
    print(f'Scanning {len(addr_list)} addresses -> {addr_list[0]} - {addr_list[-1]}')

    threads = []
    
    for addr in progressbar.progressbar(addr_list):
        if len(threads) > MAX_THREADS:
            threads.pop(0).join()

        thread = Thread(target=scan_addr, args=(addr,port_scan, results))
        thread.start()
        threads.append(thread)

    with progressbar.ProgressBar(max_value=len(threads)) as bar:
        for i, thread in enumerate(threads):
            thread.join()
            bar.update(i)
        
    results = sorted(results, key=lambda x: int(x['addr'].replace('.','')))
    for res in results:
        if res['up']:
            print(colored(res['addr'], 'blue'), colored(res['hostname'], 'red'))
            if port_scan:
                for port in res['ports']:
                    print("  -> ",colored(port, 'green'))

def scan_addr(ip, port_scan, results):
    try:
        result = ping(ip, count=3,verbose=False, timeout=1)
        ports = []
        threads = []
        
        if result.success() and port_scan:
            for port in [21,22,80,443,110,993,25,587,3306]:       
                thread = Thread(target=scan_port, args=(ip,port,ports))
                thread.start()
                threads.append(thread)
                
            for thread in threads:
                thread.join()
        hostname = ""
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass
        
        res = {'up': result.success(), 'addr': ip, 'ports': sorted(ports), 'hostname': hostname}
        results.append(res)
    except Exception as e:
        pass

def scan_port(ip,port, results):
    s = socket.socket()
    try:
        s.connect((ip,port))
        s.close()
        results.append(port)
    except:
        pass

def gen_addr(addr_list):
    if len(addr_list) == 0:
        return addr_list
    if not '*' in addr_list[0]:
        return addr_list

    ret_list = []
    for addr in addr_list:
        for i in range(1,256):
            ip = addr.replace('*', str(i), 1)
            ret_list.append(ip)

    return gen_addr(ret_list)

if __name__ == '__main__':
    main()
