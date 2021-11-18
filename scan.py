#!/usr/bin/env python3

# @author Tilo-K

from pythonping import ping
from socket import socket
import argparse

def main():
    parser = argparse.ArgumentParser(description="A hand made tool to scan a Network")
    parser.add_argument('addresses', metavar='address',type=str, help='The address space to be scanned.')

    args = parser.parse_args()

    addresses = args.addresses

    normal_scan(addresses)


def normal_scan(addresses):
    addr_list = gen_addr([addresses])

    print(f'Scanning {len(addr_list)} addresses -> {addr_list[0]} - {addr_list[-1]}')

    for addr in addr_list:
        print(scan_addr(addr))

def scan_addr(ip):
   result = ping(ip, count=1)

   return result

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
