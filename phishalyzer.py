import sys
from argparse import ArgumentParser
import re
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import dns.resolver
import os

def getFile(eHeader):
    try:
        with open(eHeader, 'r', encoding='UTF-8') as header:
            lines =  header.read().splitlines()

        return ''.join(lines).lower()
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

def resolveIP(domain):
    try:
        resolve4 = dns.resolver.resolve(domain, 'A')
        resolve6 = dns.resolver.resolve(domain, 'AAAA')
        if resolve4:
            for ipv4 in resolve4:
                return f'({ipv4})'
        if resolve4 is None and resolve6:
            for ipv6 in resolve6:
                return f'({ipv6})'
    except:
        return f'{Fore.LIGHTRED_EX}(No IP){Fore.RESET}'
    

def routing(header):
    
    routing = []

    receivedMatch = re.findall(r'received: from ([\w\-.:]+)', header)
    byMatch = re.findall(r'by ([\w\-.:]+)', header)
    withMatch = re.findall(r'with ([\w\-.:]+)', header)
    ip = re.findall(r'received: from ([\w\-.:]+) [\(\[]([\w\.:]+)[\)\]]', header)

    print(f'\n{Fore.LIGHTBLUE_EX}Relay Routing: {Fore.RESET}')
    

    for hopsCount, (amountReceived, amountBy, amountWith) in enumerate(zip(reversed(receivedMatch), reversed(byMatch), reversed(withMatch)), start=1):
        print(f'Hop {hopsCount} |↓|: FROM {Fore.GREEN}{amountReceived}{Fore.RESET} {resolveIP(amountReceived)} TO {Fore.GREEN}{amountBy}{Fore.RESET} {resolveIP(amountBy)} WITH {Fore.CYAN}{amountWith}{Fore.RESET}')
        routing.append(f'Hop {hopsCount} |↓|: FROM {amountReceived} {resolveIP(amountReceived)} TO {amountBy} {resolveIP(amountBy)} WITH {amountWith}')

    return '\n'.join(routing)


def envelopeFrom(header):
    envelopeFromMatch = re.findall(r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?", header)
    for form in enumerate(envelopeFromMatch, start=1):
        print(f'{form[1]}')

def main():

    parser = ArgumentParser() #Create the Parser.

    parser.add_argument('-f', '--file')
    parser.add_argument('-a', '--analyze', action='store_true')

    args = parser.parse_args() #initialize the Parser.

    if args.file is not None and args.analyze is not None:
        print(f'{Fore.YELLOW}\nE-Mail Header Analyse complete{Fore.RESET}')
        #routing(getFile(args.file))
        print(envelopeFrom(getFile(args.file)))
        #print(getFile(args.file))
        #print(resolveIP('PAWP194MB2202.EURP194.PROD.OUTLOOK.COM'.lower()))
    else:
        parser.error('E-Mail Header is required.')


if __name__ == '__main__':
    colorama_init()
    main()