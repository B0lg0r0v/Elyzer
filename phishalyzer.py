import sys
from argparse import ArgumentParser
import re
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

colorama_init()

def getFile(eHeader):
    with open(eHeader, 'r', encoding='UTF-8') as header:
        lines =  header.read().splitlines()

    return ''.join(lines)

def routing(header):
    
    receivedMatch = re.findall(r'Received: from ([\w\-.:]+)', header)
    byMatch = re.findall(r'by ([\w\-.:]+)', header)
    withMatch = re.findall(r'with ([\w\/]+);', header)

    for hopsCount, (amountReceived, amountBy, amountWith) in enumerate(zip(reversed(receivedMatch), reversed(byMatch), withMatch), start=1):
        print(f'Hop {hopsCount}: FROM {amountReceived} BY {amountBy} WITH {amountWith}')

    return None

def main():

    parser = ArgumentParser() #Create the Parser.

    parser.add_argument('-f', '--file')
    parser.add_argument('-a', '--analyze', action='store_true')

    args = parser.parse_args() #initialize the Parser.

    if args.file is not None and args.analyze is not None:
        routing(getFile(args.file))
        #print(getFile(args.file))

    else:
        parser.error('E-Mail Header is required.')

    


main()