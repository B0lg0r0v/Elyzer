import sys
from argparse import ArgumentParser
import re
from colorama import init as colorama_init
from colorama import Fore
import dns.resolver
import os
from datetime import datetime
from email.parser import BytesParser


def getReceivedFields(eHeader):
    # credits goes to spcnvdr for helping me with this part of the code. https://github.com/spcnvdr/tracemail/tree/master Copyright 2020 spcnvdr <spcnvdrr@protonmail.com>

    #------------------------get all the "Receveid: from" Fields------------------------# 

    found = False
    tmp = ''
    receivedFields =[]
    finalReceivedFields = []
    fields = getFields(eHeader)

    with open(eHeader, 'r', encoding='UTF-8') as header:
        for lines in header:
            separator = lines.split()
            
            if len(separator) != 0 and separator[0] in fields and found:
                receivedFields.append(tmp)
                tmp =''
                if separator[0] != 'Received:':
                    found = False            
                else:
                    tmp += lines
            elif found:
                tmp += lines
            elif 'Received:' in lines.split():
                found = True
                tmp += lines

    for x in receivedFields:
        finalReceivedFields.append(' '.join(x.split()))

    return finalReceivedFields


#------------------------get all the fields------------------------#

def getFields(filename):
    fields = []
    # First find all the fields present in the email headers
    with open(filename, "rb") as fp:
        headers = BytesParser().parse(fp)

    # Add each field to a list
    for j in headers:
        fields.append(j + ":")

    return fields


#------------------------resolve to IPv4------------------------#

def resolveIP(domain):
    try:
        resolve4 = dns.resolver.resolve(domain, 'A')
        #resolve6 = dns.resolver.resolve(domain, 'AAAA')
        if resolve4:
            for resolved4 in resolve4:
                return f'{resolved4}'
    except:
        return f'{Fore.LIGHTRED_EX}Error.{Fore.RESET}'
    
#------------------------Routing Information & Timestamps------------------------#
def routing(eHeader):
    
    routing =[]
    counter= 0 # counter for the hops

    print(f'\n{Fore.LIGHTBLUE_EX}Relay Routing: {Fore.RESET}')
    routing.append(f'Relay Routing:\n')

    for y in reversed(getReceivedFields(eHeader)):
        
        # Regex for the field values
        receivedMatch = re.findall(r'received: from ([\w\-.:]+)', y, re.IGNORECASE)
        byMatch = re.findall(r'by ([\w\-.:]+)', y, re.IGNORECASE)
        withMatch = re.findall(r'with ([\w\-.:]+)', y, re.IGNORECASE)

        counter += 1 
        if len(receivedMatch) != 0:
            print(f'Hop {counter} |↓|: FROM {Fore.GREEN}{receivedMatch[0].lower()}{Fore.RESET} TO {Fore.GREEN}{byMatch[0].lower()}{Fore.RESET} WITH {Fore.CYAN}{withMatch[0].lower()}{Fore.RESET}')
            routing.append(f'Hop {counter} |↓|: FROM {receivedMatch[0].lower()} TO {byMatch[0].lower()} WITH {withMatch[0].lower()}')
        else:
            print('No match found')
      
    print(f'\n{Fore.LIGHTBLUE_EX}Timestamps between Hops: {Fore.RESET}')
    routing.append(f'\nTimestamps between Hops:')

    dateCounter = 1 #separate counter for the hops in the timestamps

    for x in reversed(getReceivedFields(eHeader)):
        dateMatch1 = re.findall(r'\S{3},[ ]{0,4} \d{1,2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2} [+-]\d{4}', x ,re.IGNORECASE)
        dateMatch2 = re.findall(r'\S{3}, \d{2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)
        dateMatch3 = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)

        if dateMatch1 is not None:
            for date in reversed(dateMatch1):
                print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}')
                dateCounter += 1
        
        elif dateMatch2 is not None:
            for date in reversed(dateMatch2):
                print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}')
                dateCounter += 1

        elif dateMatch3 is not None:
            for date in reversed(dateMatch3):
                print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}')
                dateCounter += 1


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

    if content['received-spf'] is not None:
        if 'fail' in content['received-spf'].lower():
            print(f'Received SPF: {Fore.LIGHTRED_EX}{content["received-spf"]}{Fore.RESET}')
        else:
            print(f'Received SPF: {Fore.GREEN}{content["received-spf"]}{Fore.RESET}')
    else:
        print(f'Received SPF: {Fore.LIGHTRED_EX}No Received SPF{Fore.RESET}')


    if content['dkim-signature'] is not None:
        print(f'DKIM Signature: {Fore.GREEN}{content["dkim-signature"]}{Fore.RESET}')
    else:
        print(f'DKIM Signature: {Fore.LIGHTRED_EX}No DKIM Signature{Fore.RESET}')
    

    if content['dmarc'] is not None:
        print(f'DMARC: {Fore.GREEN}{content["dmarc"]}{Fore.RESET}')
    else:
        print(f'DMARC: {Fore.LIGHTRED_EX}No DMARC{Fore.RESET}')
    

    if content['authentication-results'] is not None:
        
        if 'spf=fail' in content['authentication-results'].lower():
            print(f'Authentication Results: {Fore.LIGHTRED_EX}{content["authentication-results"]}{Fore.RESET}')
        else:
            print(f'Authentication Results: {Fore.GREEN}{content["authentication-results"]}{Fore.RESET}')
            
    else:
        print(f'Authentication Results: {Fore.LIGHTRED_EX}No Authentication Results{Fore.RESET}')

    
    if content['x-forefront-antispam-report'] is not None:
        print(f'X-Forefront-Antispam-Report: {Fore.GREEN}{content["x-forefront-antispam-report"]}{Fore.RESET}')
    else:
        print(f'X-Forefront-Antispam-Report: {Fore.LIGHTRED_EX}No X-Forefront-Antispam-Report{Fore.RESET}')


    if content['x-microsoft-antispam'] is not None:
        print(f'X-Microsoft-Antispam: {Fore.GREEN}{content["x-microsoft-antispam"]}{Fore.RESET}')
    else:
        print(f'X-Microsoft-Antispam: {Fore.LIGHTRED_EX}No X-Microsoft-Antispam{Fore.RESET}')


def envelope(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}Interesting Headers: {Fore.RESET}')


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
    
    print(f'{Fore.CYAN}\n<-------------------------------------------------->\n{Fore.RESET}')



def spoofing(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}Phishing Check: {Fore.RESET}')

    #------------------------Regex and Field definitions------------------------#

    x = next(iter(reversed(getReceivedFields(eheader))), None)
    ipv4 = re.findall(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]', x, re.IGNORECASE)
    ipv6 = re.findall(r'[\[\(]([A-Fa-f0-9:]+)[\]\)]', x, re.IGNORECASE)
    
    formatReturnPath = False
    formatReplyTo = False
    
 
    fromMatch = re.search(r'<(.*)>', content['from'])
    if content['return-path'] is not None:
        if '<' in content['return-path']:
            returnToPath = re.search(r'<(.*?)>', content['return-path'])
            formatReturnPath = True
    if content['reply-to'] is not None:
        if '<' in content['reply-to']:
            replyTo = re.search(r'<(.*)>', content['reply-to'])
            formatReplyTo = True


    #------------------------check for spoofing------------------------#
    mx = []
    aRecordsOfMx = []

    # Getting the Domain Name from the "From" Field
    fromEmailDomain = fromMatch.group(1).split('@')[1]
    # Getting the MX Records from the Domain Name
    try:
        getMx = dns.resolver.resolve(fromEmailDomain, 'MX')
        for servers in getMx:
            mx.append(servers.exchange.to_text().lower())

    except dns.resolver.LifetimeTimeout:
        print(f'{Fore.LIGHTRED_EX}Could not resolve the MX Record.{Fore.RESET}')
    # Resolving the A Records from the MX Records  
    for servers in mx:
        aRecordsOfMx.append(resolveIP(servers))
        
    
    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for SMTP Server Mismatch...{Fore.RESET}')

    if ipv4:
        if ipv4[0] in aRecordsOfMx:
            print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
        else:
            print(f'{Fore.LIGHTYELLOW_EX}SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(ipv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.) {Fore.RESET}')

    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for Field Mismatches...{Fore.RESET}')


    indent = ' ' * 3
    
    if fromMatch.group(1) is not None and content['reply-to'] is not None:
       
        print(f'{Fore.LIGHTGREEN_EX}Reply-To Field detected{Fore.RESET}')
        
        if formatReplyTo == False:
            if content['from'] != content['reply-to']:
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]}){Fore.RESET}')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')

        elif formatReplyTo == True:
            if fromMatch.group(1) != replyTo.group(1):
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)}){Fore.RESET}')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')

    else:
        print(f'{Fore.WHITE}No Reply-To Field detected. Skipping...{Fore.RESET}')

    if fromMatch.group(1) is not None and content['return-path'] is not None:
      
        print(f'{Fore.LIGHTGREEN_EX}Return-Path Field detected{Fore.RESET}')
      
        if formatReturnPath == False:
            if fromMatch.group(1) != content['return-path']:
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]}){Fore.RESET}')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - RETURN-PATH" Mismatch detected.{Fore.RESET}')
        
        elif formatReturnPath == True:
            if fromMatch.group(1) != returnToPath.group(1):
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)}){Fore.RESET}')
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - RETURN-PATH" Mismatch detected.{Fore.RESET}')

    else:
        print(f'{Fore.WHITE}No Return-Path Field detected. Skipping...{Fore.RESET}')
       
    #------------------------Check with VirusTotal------------------------#

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with VirusTotal...{Fore.RESET}')

    if ipv4:
        # If you got an VT API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
        #os.system(f'curl -s -X GET --header "x-apikey: <Your API KEY>" "https://www.virustotal.com/api/v3/ip_addresses/{ipv4[0]}" > vt.json')
        print(f'{Fore.LIGHTYELLOW_EX}Note: You can use your own VirusTotal API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}\n')
        print(f'Detections: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/detection{Fore.RESET}')
        print(f'Relations: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/relations{Fore.RESET}')
        print(f'Graph: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/graph{Fore.RESET}')
        print(f'Network Traffic: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/network-traffic{Fore.RESET}')
        print(f'WHOIS: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/whois{Fore.RESET}')
        print(f'Comments: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/comments{Fore.RESET}')
        print(f'Votes: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{ipv4[0]}/votes{Fore.RESET}')

    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')

    #------------------------Check with AbuseIPDB------------------------#

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with AbuseIPDB...{Fore.RESET}')

    if ipv4:
        # If you got an AbuseIPDB API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
        #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://api.abuseipdb.com/api/v2/check?ipAddress={ipv4[0]}" > abuseipdb.json')
        print(f'{Fore.LIGHTYELLOW_EX}Note: You can use your own AbuseIPDB API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}\n')
        print(f'AbuseIPDB: {Fore.LIGHTGREEN_EX}https://www.abuseipdb.com/check/{ipv4[0]}{Fore.RESET}')
        
    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')

    #------------------------Check with IPQualityScore------------------------#

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with IPQualityScore...{Fore.RESET}')

    if ipv4:
        # If you got an IPQualityScore API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
        #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://www.ipqualityscore.com/api/json/ip/<Your API KEY>/{ipv4[0]}" > ipqualityscore.json')
        print(f'{Fore.LIGHTYELLOW_EX}Note: You can use your own IPQualityScore API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}\n')
        print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ipv4[0]}{Fore.RESET}')

    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')

    

if __name__ == '__main__':

    print(r"""
          
   ____ ____  __ ____   ____ ___ 
  / __// /\ \/ //_  /  / __// _ \
 / _/ / /__\  /  / /_ / _/ / , _/
/___//____//_/  /___//___//_/|_| v0.1
                                  

    Author: B0lg0r0v
    https://root.security
    """)
    print("\n")

    colorama_init() #initialize colorama

    parser = ArgumentParser() #Create the Parser.
    parser.add_argument('-f', '--file', help='give the E-Mail Header as a file.', required=True)
    parser.add_argument('-v', '--version', action='version', version='Elyzer v0.1')
    args = parser.parse_args() #initialize the Parser.

    if args.file is not None:  
        print(f'{Fore.YELLOW}E-Mail Header Analysis complete{Fore.RESET}')

        geeneralInformation(args.file)
        routing(args.file)
        securityInformations(args.file)
        envelope(args.file)
        spoofing(args.file)

    else:
        parser.error('E-Mail Header is required.')