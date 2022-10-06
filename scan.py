#!/usr/bin/env python3

# @author Tilo-K

from gufo.ping import Ping
import socket
import argparse
import asyncio
import os
from termcolor import colored

ping = Ping()


async def main():
    parser = argparse.ArgumentParser(
        description="A hand made tool to scan a Network")
    parser.add_argument('addresses', metavar='address',
                        type=str, help='The address space to be scanned.')
    parser.add_argument('--ports', dest='ports', action='store_true')
    parser.set_defaults(ports=False)

    args = parser.parse_args()

    addresses = args.addresses
    port_scan = args.ports
    await normal_scan(addresses, port_scan)


async def normal_scan(addresses, port_scan):
    try:
        int(addresses.replace('.', '').replace('*', ''))
    except ValueError:
        addresses = socket.gethostbyname(addresses)

    addr_list = gen_addr([addresses])
    results = []
    print(
        f'Scanning {len(addr_list)} addresses -> {addr_list[0]} - {addr_list[-1]}')

    tasks = []

    for addr in addr_list:
        task = asyncio.create_task(scan_addr(addr, port_scan, results))
        tasks.append(task)

    await asyncio.gather(*tasks)

    results = sorted(results, key=lambda x: int(x['addr'].replace('.', '')))
    columns, _ = os.get_terminal_size()
    print('\n\n' + colored('*'*columns, 'blue'))
    for res in results:
        if res['up']:
            print(colored(res['addr'], 'blue'),
                  colored(res['hostname'], 'red'))
            if port_scan:
                for port in res['ports']:
                    print("  -> ", colored(port, 'green'))


async def scan_addr(ip, port_scan, results):
    try:
        result = await ping.ping(ip)
        ports = []
        tasks = []

        if result is not None and port_scan:
            for port in [21, 22, 80, 443, 110, 993, 25, 587, 3306]:
                task = asyncio.create_task(scan_port(ip, port, ports))
                tasks.append(task)

            await asyncio.gather(*tasks)
        hostname = ""

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass

        res = {'up': result is not None, 'addr': ip, 'ports': sorted(ports),
               'hostname': hostname}
        print('Scanned ip: ', ip, ' '*10, end='\r')
        results.append(res)
    except Exception as e:
        print(e)


async def scan_port(ip, port, results):
    s = socket.socket()
    try:
        s.connect((ip, port))
        s.close()
        results.append(port)
    except ConnectionError:
        pass


def gen_addr(addr_list):
    if len(addr_list) == 0:
        return addr_list
    if '*' not in addr_list[0]:
        return addr_list

    ret_list = []
    for addr in addr_list:
        for i in range(0, 256):
            ip = addr.replace('*', str(i), 1)
            ret_list.append(ip)

    return gen_addr(ret_list)


if __name__ == '__main__':
    asyncio.run(main())
