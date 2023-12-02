import sys
from argparse import ArgumentParser
import re
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import dns.resolver
import os
from datetime import datetime
from email.parser import BytesParser


def resolveIP(domain):
    try:
        resolve4 = dns.resolver.resolve(domain, 'A')
        #resolve6 = dns.resolver.resolve(domain, 'AAAA')
        if resolve4:
            for resolved4 in resolve4:
                return f'{resolved4}'
    except:
        return f'{Fore.LIGHTRED_EX}(No IP){Fore.RESET}'
    

def routing(eHeader):
    
    try:
        with open(eHeader, 'r', encoding='UTF-8') as content:
            tmp =  content.read().splitlines()

    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    header = ''.join(tmp).lower()
    routing = []

    receivedMatch = re.findall(r'received: from ([\w\-.:]+)', header)
    byMatch = re.findall(r'by ([\w\-.:]+)', header)
    withMatch = re.findall(r'with ([\w\-.:]+)', header)


    print(f'\n{Fore.LIGHTBLUE_EX}Relay Routing: {Fore.RESET}')
    routing.append(f'Relay Routing:\n')

    for hopsCount, (amountReceived, amountBy, amountWith) in enumerate(zip(reversed(receivedMatch), reversed(byMatch), reversed(withMatch)), start=1):
        print(f'Hop {hopsCount} |↓|: FROM {Fore.GREEN}{amountReceived}{Fore.RESET} {resolveIP(amountReceived)} TO {Fore.GREEN}{amountBy}{Fore.RESET} {resolveIP(amountBy)} WITH {Fore.CYAN}{amountWith}{Fore.RESET}')
        routing.append(f'Hop {hopsCount} |↓|: FROM {amountReceived} {resolveIP(amountReceived)} TO {amountBy} {resolveIP(amountBy)} WITH {amountWith}')
      

    dateMatch1 = re.findall(r'\S{3},[ ]{0,4} \d{1,2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2} [+-]\d{4}', header)
    dateMatch2 = re.findall(r'\S{3}, \d{2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', header)
    dateMatch3 = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', header)

    print(f'\n{Fore.LIGHTBLUE_EX}Timestamps between Hops: {Fore.RESET}')
    routing.append(f'\nTimestamps between Hops:')

    if dateMatch1 is not None:
        for counter, date in enumerate(reversed(dateMatch1[:hopsCount]), start=1):
            print(f'Hop {counter}: {Fore.GREEN}{date}{Fore.RESET}')
            routing.append(f'Hop {counter}: {date}')
    
    elif dateMatch2 is not None:
        for counter, date in enumerate(reversed(dateMatch2[:hopsCount]), start=1):
            print(f'Hop {counter}: {Fore.GREEN}{date}{Fore.RESET}')
            routing.append(f'Hop {counter}: {date}')
    
    elif dateMatch3 is not None:
        for counter, date in enumerate(reversed(dateMatch3[:hopsCount]), start=1):
            print(f'Hop {counter}: {Fore.GREEN}{date}{Fore.RESET}')
            routing.append(f'Hop {counter}: {date}')
            


    return '\n'.join(routing)


def geeneralInformation(eheader):
    
    gInformation =[]

    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}General Information: {Fore.RESET}')

    print(f'From: {Fore.GREEN}{content["from"]}{Fore.RESET}')
    print(f'To: {Fore.GREEN}{content["to"]}{Fore.RESET}')
    print(f'Subject: {Fore.GREEN}{content["subject"]}{Fore.RESET}')
    print(f'Date: {Fore.GREEN}{content["date"]}{Fore.RESET}')

    gInformation.append(f'From: {content["from"]}\n' + f'To: {content["to"]}\n' + f'Subject: {content["subject"]}\n' + f'Date: {content["date"]}\n')
    
    return '\n'.join(gInformation)


def securityInformations(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)


    print(f'\n{Fore.LIGHTBLUE_EX}Security Informations: {Fore.RESET}')

    if content['authentication-results'] is not None:
        
        if 'spf=fail' in content['authentication-results'].lower():
            print(f'Authentication Results: {Fore.LIGHTRED_EX}{content["authentication-results"]}{Fore.RESET}')
        else:
            print(f'Authentication Results: {Fore.GREEN}{content["authentication-results"]}{Fore.RESET}')
            
    else:
        print(f'Authentication Results: {Fore.LIGHTRED_EX}No Authentication Results{Fore.RESET}')


    if content['dkim-signature'] is not None:
        print(f'DKIM Signature: {Fore.GREEN}{content["dkim-signature"]}{Fore.RESET}')
    else:
        print(f'DKIM Signature: {Fore.LIGHTRED_EX}No DKIM Signature{Fore.RESET}')
    
    if content['received-spf'] is not None:
        if 'fail' in content['received-spf'].lower():
            print(f'Received SPF: {Fore.LIGHTRED_EX}{content["received-spf"]}{Fore.RESET}')
        else:
            print(f'Received SPF: {Fore.GREEN}{content["received-spf"]}{Fore.RESET}')
    else:
        print(f'Received SPF: {Fore.LIGHTRED_EX}No Received SPF{Fore.RESET}')
    
    if content['x-forefront-antispam-report'] is not None:
        print(f'X-Forefront-Antispam-Report: {Fore.GREEN}{content["x-forefront-antispam-report"]}{Fore.RESET}')
    else:
        print(f'X-Forefront-Antispam-Report: {Fore.LIGHTRED_EX}No X-Forefront-Antispam-Report{Fore.RESET}')
    
    if content['dmarc'] is not None:
        print(f'DMARC: {Fore.GREEN}{content["dmarc"]}{Fore.RESET}')
    else:
        print(f'DMARC: {Fore.LIGHTRED_EX}No DMARC{Fore.RESET}')


def envelope(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}Envelope Information: {Fore.RESET}')


    if content['X-ORIG-EnvelopeFrom'] is not None:
        fromMatch = re.search(r'<(.*)>', content['from'])

        if content['X-ORIG-EnvelopeFrom'] == 'anonymous@':
            print(f'{Fore.LIGHTRED_EX}Envelope From: {Fore.LIGHTYELLOW_EX}{content["X-ORIG-EnvelopeFrom"]}{Fore.RESET}')
        
        elif content['X-ORIG-EnvelopeFrom'] != fromMatch.group(1):
            print(f'{Fore.RED}POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content["from"]}) NOT EQUAL ({content["X-ORIG-EnvelopeFrom"]}){Fore.RESET}')

        else:
            print(f'Envelope From: {Fore.GREEN}{content["X-ORIG-EnvelopeFrom"]}{Fore.RESET}')
    else:
        print(f'Envelope From: {Fore.LIGHTRED_EX}No Envelope From{Fore.RESET}')


    if content['return-path'] is not None:
        print(f'Return Path: {Fore.GREEN}{content["return-path"]}{Fore.RESET}')
    else:
        print(f'Return Path: {Fore.LIGHTRED_EX}No Return Path{Fore.RESET}')

    if content['message-id'] is not None:
        print(f'Message ID: {Fore.GREEN}{content["message-id"]}{Fore.RESET}')
    else:
        print(f'Message ID: {Fore.LIGHTRED_EX}No Message ID{Fore.RESET}')

    if content['mime-version'] is not None:
        print(f'MIME-Version: {Fore.GREEN}{content["mime-version"]}{Fore.RESET}')
    else:
        print(f'MIME-Version: {Fore.LIGHTRED_EX}No MIME-Version{Fore.RESET}')


    print(f'{Fore.CYAN}\n<---------MS Exchange Organization Headers--------->\n{Fore.RESET}')

    if content['x-ms-exchange-organization-authas'] is not None:
        if 'anonymous' or 'Anonymous' in content['x-ms-exchange-organization-authas']:
            print(f'X-MS-Exchange-Organization-AuthAs: {Fore.LIGHTYELLOW_EX}{content["x-ms-exchange-organization-authas"]}{Fore.RESET}')
        else:
            print(f'X-MS-Exchange-Organization-AuthAs: {Fore.GREEN}{content["x-ms-exchange-organization-authas"]}{Fore.RESET}')
    else:
        print(f'X-MS-Exchange-Organization-AuthAs: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthAs{Fore.RESET}')

    if content['x-ms-exchange-organization-authsource'] is not None:
        print(f'X-MS-Exchange-Organization-AuthSource: {Fore.GREEN}{content["x-ms-exchange-organization-authsource"]}{Fore.RESET}')
    else:
        print(f'X-MS-Exchange-Organization-AuthSource: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthSource{Fore.RESET}')

    if content['x-ms-exchange-organization-authmechanism'] is not None:
        print(f'X-MS-Exchange-Organization-AuthMechanism: {Fore.GREEN}{content["x-ms-exchange-organization-authmechanism"]}{Fore.RESET}')
    else:
        print(f'X-MS-Exchange-Organization-AuthMechanism: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthMechanism{Fore.RESET}')

    if content['x-ms-exchange-organization-network-message-id'] is not None:
        print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.GREEN}{content["x-ms-exchange-organization-network-message-id"]}{Fore.RESET}')
    else:
        print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-Network-Message-Id{Fore.RESET}')
    


def spoofing(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}Phishing Check: {Fore.RESET}')
    
    fromMatch = re.search(r'<(.*)>', content['from'])
   
    #print(content['Received: from'])

    if fromMatch.group(1) is not None and content['reply-to'] is not None:
        if content['from'] != content['reply-to']:
            print(f'{Fore.LIGHTYELLOW_EX}Suspicous activity detected: FROM Field({fromMatch.group(1)}) NOT EQUAL REPLY-TO Field ({content["reply-to"]}){Fore.RESET}')
        else:
            pass

    if fromMatch.group(1) is not None and content['return-path'] is not None:
        if fromMatch.group(1) != content['return-path']:
            print(f'{Fore.LIGHTYELLOW_EX}Suspicous activity detected: FROM Field({fromMatch.group(1)}) NOT EQUAL RETURN-PATH Field ({content["return-path"]}){Fore.RESET}')
        else:
            pass
       

    

def main():

    parser = ArgumentParser() #Create the Parser.

    parser.add_argument('-f', '--file')
    parser.add_argument('-a', '--analyze', action='store_true')

    args = parser.parse_args() #initialize the Parser.

    if args.file is not None and args.analyze is not None:
        print(f'{Fore.YELLOW}\nE-Mail Header Analyse complete{Fore.RESET}')
        
        geeneralInformation(args.file)
        routing(args.file)
        securityInformations(args.file)
        envelope(args.file)
        spoofing(args.file)
        #print(getFile(args.file))
        #print(resolveIP('mail-oa1-f45.google.com'.lower()))
        #print(extract_date(getFile(args.file)))
    else:
        parser.error('E-Mail Header is required.')



if __name__ == '__main__':
    colorama_init()

    
    main()