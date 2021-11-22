#!/usr/bin/env python3

# @author Tilo-K

from pythonping import ping
from socket import socket
import argparse
import asyncio
import progressbar

async def main():
    parser = argparse.ArgumentParser(description="A hand made tool to scan a Network")
    parser.add_argument('addresses', metavar='address',type=str, help='The address space to be scanned.')

    args = parser.parse_args()

    addresses = args.addresses

    await normal_scan(addresses)


async def normal_scan(addresses):
    addr_list = gen_addr([addresses])
    results = []
    print(f'Scanning {len(addr_list)} addresses -> {addr_list[0]} - {addr_list[-1]}')

    tasks = []

    for addr in addr_list:
        task = asyncio.create_task(scan_addr(addr))
        tasks.append(task)

    with progressbar.ProgressBar(max_value=len(tasks)) as bar:
        for i, task in enumerate(tasks):
            results.append(await task)
            bar.update(i)
        

    for res in results:
        if res['up']:
            print(res['addr'])

async def scan_addr(ip):
   result = ping(ip, count=1,verbose=False, timeout=0.5)
   res = {'up': result.success(), 'addr': ip}
   return res

async def scan_port(ip,port):
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
    asyncio.run(main())
