#!/usr/bin/env python3

# @author Tilo-K

from pythonping import ping
from socket import socket
import argparse
from threading import Thread
import progressbar

def main():
    parser = argparse.ArgumentParser(description="A hand made tool to scan a Network")
    parser.add_argument('addresses', metavar='address',type=str, help='The address space to be scanned.')

    args = parser.parse_args()

    addresses = args.addresses

    normal_scan(addresses)


def normal_scan(addresses):
    addr_list = gen_addr([addresses])
    results = []
    print(f'Scanning {len(addr_list)} addresses -> {addr_list[0]} - {addr_list[-1]}')

    threads = []

    for addr in addr_list:
        thread = Thread(target=scan_addr, args=(addr, results))
        thread.start()
        threads.append(thread)

    with progressbar.ProgressBar(max_value=len(threads)) as bar:
        for i, thread in enumerate(threads):
            thread.join()
            bar.update(i)
        

    for res in results:
        if res['up']:
            print(res['addr'])

def scan_addr(ip, results):
   result = ping(ip, count=1,verbose=False, timeout=0.5)
   res = {'up': result.success(), 'addr': ip}
   results.append(res)

def scan_port(ip,port):
    s = socket.socket()
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
