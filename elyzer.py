import sys
from argparse import ArgumentParser
import re
from colorama import init as colorama_init
from colorama import Fore
import dns.resolver
import requests
import json
from datetime import datetime
from email.parser import BytesParser
import ipaddress
from email.header import decode_header
import hashlib

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
        try:
            if len(receivedMatch) != 0:
                print(f'Hop {counter} |↓|: FROM {Fore.GREEN}{receivedMatch[0].lower()}{Fore.RESET} TO {Fore.GREEN}{byMatch[0].lower()}{Fore.RESET} WITH {Fore.CYAN}{withMatch[0].lower()}{Fore.RESET}')
                routing.append(f'Hop {counter} |↓|: FROM {receivedMatch[0].lower()} TO {byMatch[0].lower()} WITH {withMatch[0].lower()}\n')
            else:
                print(f'{Fore.LIGHTYELLOW_EX}No match found for Hop {counter}{Fore.RESET}')
        except Exception as e:
            print(f'{Fore.LIGHTRED_EX}Error: {e}. Skipping...{Fore.RESET}')
      
    print(f'\n{Fore.LIGHTBLUE_EX}Timestamps between Hops: {Fore.RESET}')
    routing.append(f'\nTimestamps between Hops:\n')

    dateCounter = 1 #separate counter for the hops in the timestamps
    prevTimestamp = None
    delta = None

    for x in reversed(getReceivedFields(eHeader)):
        dateMatch1 = re.findall(r'\S{3},[ ]{0,4} \d{1,2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2} [+-]\d{4}', x ,re.IGNORECASE)
        dateMatch2 = re.findall(r'\S{3}, \d{2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)
        dateMatch3 = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)

        if dateMatch1 is not None:
            for date in reversed(dateMatch1):
                currentTimeStamp = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z')
                if prevTimestamp:
                    delta = currentTimeStamp - prevTimestamp
                    print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}, {Fore.CYAN}Delta: {delta}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}, Delta: {delta if delta is not None else "N/A"}\n')
                dateCounter += 1
                prevTimestamp = currentTimeStamp
        
        elif dateMatch2 is not None:
            for date in reversed(dateMatch2):
                currentTimeStamp = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S.%f %z')
                if prevTimestamp:
                    delta = currentTimeStamp - prevTimestamp
                    print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}, {Fore.CYAN}Delta: {delta}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}, Delta: {delta if delta is not None else "N/A"}\n')
                dateCounter += 1
                prevTimestamp = currentTimeStamp

        elif dateMatch3 is not None:
            for date in reversed(dateMatch3):
                currentTimeStamp = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f %z')
                if prevTimestamp:
                    delta = currentTimeStamp - prevTimestamp
                    print(f'Hop {dateCounter}: {Fore.GREEN}{date}{Fore.RESET}, {Fore.CYAN}Delta: {delta}{Fore.RESET}')
                routing.append(f'Hop {dateCounter}: {date}\n, Delta: {delta if delta is not None else "N/A"}\n')
                dateCounter += 1
                prevTimestamp = currentTimeStamp

    return ''.join(routing)


def generalInformation(eheader):
    
    gInformation = []

    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    # Trying to decode the subject. This is far from perfect, but it works for most cases.
    subject = content.get('subject')
    if subject is not None:
        decoded_subject = decode_header(subject)
        decodedHeader = ''
        for part, charset in decoded_subject:
            try:
                decodedHeader += part.decode(charset or 'utf8') if isinstance(part, bytes) else part
            except UnicodeDecodeError:
                decodedHeader += part.decode('iso-8859-1') if isinstance(part, bytes) else part
    else:
        decodedHeader = None
    
    #decodedHeader = ''.join([s[0].decode(s[1] or 'utf-8') if isinstance(s[0], bytes) else s[0] for s in subject])
    
    print(f'\n{Fore.LIGHTBLUE_EX}General Information: {Fore.RESET}')
    gInformation.append(f'\nGeneral Information:\n')

    print(f'From: {Fore.GREEN}{content["from"]}{Fore.RESET}')
    print(f'To: {Fore.GREEN}{content["to"]}{Fore.RESET}')
    print(f'Subject: {Fore.GREEN}{decodedHeader}{Fore.RESET}')
    print(f'Date: {Fore.GREEN}{content["date"]}{Fore.RESET}')

    gInformation.append(f'From: {content["from"]}\n' + f'To: {content["to"]}\n' + f'Subject: {decodedHeader}\n' + f'Date: {content["date"]}\n')
    
    return ''.join(gInformation)


def securityInformations(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    secInfos = []

    print(f'\n{Fore.LIGHTBLUE_EX}Security Informations: {Fore.RESET}')
    secInfos.append(f'\nSecurity Informations:\n')

    if content['received-spf'] is not None:
        if 'fail' in content['received-spf'].lower():
            print(f'Received SPF: {Fore.LIGHTRED_EX}{content["received-spf"]}{Fore.RESET}')
            secInfos.append(f'Received SPF: {content["received-spf"]}')
        
        elif 'None' in content['received-spf']:
            print(f'Received SPF: {Fore.LIGHTRED_EX}{content["received-spf"]}{Fore.RESET}')
            secInfos.append(f'Received SPF: {content["received-spf"]}')

        else:
            print(f'Received SPF: {Fore.GREEN}{content["received-spf"]}{Fore.RESET}')
            secInfos.append(f'Received SPF: {content["received-spf"]}')
    else:
        print(f'Received SPF: {Fore.LIGHTRED_EX}No Received SPF{Fore.RESET}')


    if content['dkim-signature'] is not None:
        print(f'DKIM Signature: {Fore.GREEN}{content["dkim-signature"]}{Fore.RESET}')
        secInfos.append(f'DKIM Signature: {content["dkim-signature"]}')
    else:
        print(f'DKIM Signature: {Fore.LIGHTRED_EX}No DKIM Signature{Fore.RESET}')
        secInfos.append(f'DKIM Signature: No DKIM Signature')
    

    if content['dmarc'] is not None:
        print(f'DMARC: {Fore.GREEN}{content["dmarc"]}{Fore.RESET}')
        secInfos.append(f'DMARC: {content["dmarc"]}')
    else:
        print(f'DMARC: {Fore.LIGHTRED_EX}No DMARC{Fore.RESET}')
        secInfos.append(f'DMARC: No DMARC')
    

    if content['authentication-results'] is not None:
        
        if 'spf=fail' in content['authentication-results'].lower():
            print(f'Authentication Results: {Fore.LIGHTRED_EX}{content["authentication-results"]}{Fore.RESET}')
            secInfos.append(f'Authentication Results: {content["authentication-results"]}')
        else:
            print(f'Authentication Results: {Fore.GREEN}{content["authentication-results"]}{Fore.RESET}')
            secInfos.append(f'Authentication Results: {content["authentication-results"]}')
            
    else:
        print(f'Authentication Results: {Fore.LIGHTRED_EX}No Authentication Results{Fore.RESET}')
        secInfos.append(f'Authentication Results: No Authentication Results')

    
    if content['x-forefront-antispam-report'] is not None:
        print(f'X-Forefront-Antispam-Report: {Fore.GREEN}{content["x-forefront-antispam-report"]}{Fore.RESET}')
        secInfos.append(f'X-Forefront-Antispam-Report: {content["x-forefront-antispam-report"]}')
    else:
        print(f'X-Forefront-Antispam-Report: {Fore.LIGHTRED_EX}No X-Forefront-Antispam-Report{Fore.RESET}')
        secInfos.append(f'X-Forefront-Antispam-Report: No X-Forefront-Antispam-Report')


    if content['x-microsoft-antispam'] is not None:
        print(f'X-Microsoft-Antispam: {Fore.GREEN}{content["x-microsoft-antispam"]}{Fore.RESET}')
        secInfos.append(f'X-Microsoft-Antispam: {content["x-microsoft-antispam"]}')
    else:
        print(f'X-Microsoft-Antispam: {Fore.LIGHTRED_EX}No X-Microsoft-Antispam{Fore.RESET}')
        secInfos.append(f'X-Microsoft-Antispam: No X-Microsoft-Antispam')

    return '\n'.join(secInfos)


def envelope(eheader):
    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    eenvelope = []

    print(f'\n{Fore.LIGHTBLUE_EX}Interesting Headers: {Fore.RESET}')
    eenvelope.append(f'\nInteresting Headers:\n')


    if content['X-ORIG-EnvelopeFrom'] is not None:
        fromMatch = re.search(r'<(.*)>', content['from'])

        if content['X-ORIG-EnvelopeFrom'] == 'anonymous@':
            print(f'{Fore.LIGHTRED_EX}Envelope From: {Fore.LIGHTYELLOW_EX}{content["X-ORIG-EnvelopeFrom"]}{Fore.RESET}')
            eenvelope.append(f'Envelope From: {content["X-ORIG-EnvelopeFrom"]}')
        
        elif content['X-ORIG-EnvelopeFrom'] != fromMatch.group(1):
            print(f'{Fore.RED}POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content["from"]}) NOT EQUAL ({content["X-ORIG-EnvelopeFrom"]}){Fore.RESET}')
            eenvelope.append(f'POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content["from"]}) NOT EQUAL ({content["X-ORIG-EnvelopeFrom"]})')

        else:
            print(f'Envelope From: {Fore.GREEN}{content["X-ORIG-EnvelopeFrom"]}{Fore.RESET}')
            eenvelope.append(f'Envelope From: {content["X-ORIG-EnvelopeFrom"]}')
    else:
        print(f'Envelope From: {Fore.LIGHTRED_EX}No Envelope From{Fore.RESET}')
        eenvelope.append(f'Envelope From: No Envelope From')


    if content['return-path'] is not None:
        print(f'Return Path: {Fore.GREEN}{content["return-path"]}{Fore.RESET}')
        eenvelope.append(f'Return Path: {content["return-path"]}')
    else:
        print(f'Return Path: {Fore.LIGHTRED_EX}No Return Path{Fore.RESET}')
        eenvelope.append(f'Return Path: No Return Path')

    if content['message-id'] is not None:
        print(f'Message ID: {Fore.GREEN}{content["message-id"]}{Fore.RESET}')
        eenvelope.append(f'Message ID: {content["message-id"]}')
    else:
        print(f'Message ID: {Fore.LIGHTRED_EX}No Message ID{Fore.RESET}')
        eenvelope.append(f'Message ID: No Message ID')

    if content['mime-version'] is not None:
        print(f'MIME-Version: {Fore.GREEN}{content["mime-version"]}{Fore.RESET}')
        eenvelope.append(f'MIME-Version: {content["mime-version"]}')
    else:
        print(f'MIME-Version: {Fore.LIGHTRED_EX}No MIME-Version{Fore.RESET}')
        eenvelope.append(f'MIME-Version: No MIME-Version')

    if content['authentication-results-original'] is not None:
        if 'spf=fail' in content['authentication-results-original'].lower():
            print(f'Authentication-Results-Original: {Fore.LIGHTRED_EX}{content["authentication-results-original"]}{Fore.RESET}')
            eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
        
        elif 'spf=pass' in content['authentication-results-original'].lower():
            print(f'Authentication-Results-Original: {Fore.GREEN}{content["authentication-results-original"]}{Fore.RESET}')
            eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
        
        else:
            print(f'Authentication-Results-Original: {Fore.LIGHTYELLOW_EX}{content["authentication-results-original"]}{Fore.RESET}')
            eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
    else:
        print(f'Authentication-Results-Original: {Fore.LIGHTRED_EX}No Authentication-Results-Original{Fore.RESET}')
        eenvelope.append(f'Authentication-Results-Original: No Authentication-Results-Original')


    print(f'{Fore.CYAN}\n<---------MS Exchange Organization Headers--------->\n{Fore.RESET}')
    eenvelope.append(f'\n<---------MS Exchange Organization Headers--------->\n')

    if content['x-ms-exchange-organization-authas'] is not None:
        if 'anonymous' or 'Anonymous' in content['x-ms-exchange-organization-authas']:
            print(f'X-MS-Exchange-Organization-AuthAs: {Fore.LIGHTYELLOW_EX}{content["x-ms-exchange-organization-authas"]}{Fore.RESET}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: {content["x-ms-exchange-organization-authas"]}')
        else:
            print(f'X-MS-Exchange-Organization-AuthAs: {Fore.GREEN}{content["x-ms-exchange-organization-authas"]}{Fore.RESET}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: {content["x-ms-exchange-organization-authas"]}')
    else:
        print(f'X-MS-Exchange-Organization-AuthAs: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthAs{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: No X-MS-Exchange-Organization-AuthAs')

    if content['x-ms-exchange-organization-authsource'] is not None:
        print(f'X-MS-Exchange-Organization-AuthSource: {Fore.GREEN}{content["x-ms-exchange-organization-authsource"]}{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthSource: {content["x-ms-exchange-organization-authsource"]}')
    else:
        print(f'X-MS-Exchange-Organization-AuthSource: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthSource{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthSource: No X-MS-Exchange-Organization-AuthSource')

    if content['x-ms-exchange-organization-authmechanism'] is not None:
        print(f'X-MS-Exchange-Organization-AuthMechanism: {Fore.GREEN}{content["x-ms-exchange-organization-authmechanism"]}{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthMechanism: {content["x-ms-exchange-organization-authmechanism"]}')
    else:
        print(f'X-MS-Exchange-Organization-AuthMechanism: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-AuthMechanism{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-AuthMechanism: No X-MS-Exchange-Organization-AuthMechanism')

    if content['x-ms-exchange-organization-network-message-id'] is not None:
        print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.GREEN}{content["x-ms-exchange-organization-network-message-id"]}{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-Network-Message-Id: {content["x-ms-exchange-organization-network-message-id"]}')
    else:
        print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-Network-Message-Id{Fore.RESET}')
        eenvelope.append(f'X-MS-Exchange-Organization-Network-Message-Id: No X-MS-Exchange-Organization-Network-Message-Id')
    
    print(f'{Fore.CYAN}\n<-------------------------------------------------->\n{Fore.RESET}')
    eenvelope.append(f'\n<-------------------------------------------------->\n')

    return '\n'.join(eenvelope)


def spoofing(eheader):

    report = []

    try:
        with open(eheader, 'r', encoding='UTF-8') as header:
            content = BytesParser().parsebytes(header.read().encode('UTF-8'))
    except FileNotFoundError:
        print(f'{Fore.RED}File not found.{Fore.RESET}')
        sys.exit(1)

    print(f'\n{Fore.LIGHTBLUE_EX}Spoofing Check: {Fore.RESET}')
    report.append(f'\nSpoofing Check:\n')

    #------------------------Regex and Field definitions------------------------#

    x = next(iter(reversed(getReceivedFields(eheader))), None)
    ipv4 = re.findall(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]', x, re.IGNORECASE)
    ipv6 = re.findall(r'[\[\(]([A-Fa-f0-9:]+)[\]\)]', x, re.IGNORECASE)
    # get rid of the localhost IP Address
    filteredIpv4 = [ip for ip in ipv4 if ip != '127.0.0.1']

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

    mxAuthResult = []
    aRecordsOfMxAuthResult = []
    authResultOrigIP = None

    # Getting the Domain Name from the "From" Field
    fromEmailDomain = fromMatch.group(1).split('@')[1]
    # Getting the MX Records from the Domain Name
    try:
        getMx = dns.resolver.resolve(fromEmailDomain, 'MX')
        for servers in getMx:
            mx.append(servers.exchange.to_text().lower())

    except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer):
        print(f'{Fore.LIGHTRED_EX}Could not resolve the MX Record.{Fore.RESET}')
    # Resolving the A Records from the MX Records  
    for servers in mx:
        aRecordsOfMx.append(resolveIP(servers))
                 

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for SMTP Server Mismatch...{Fore.RESET}')
    report.append('\nChecking for SMTP Server Mismatch...\n')

    if filteredIpv4:
        if filteredIpv4[0] in aRecordsOfMx:
            print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
            report.append(f'No Mismatch detected.')
        else:
            print(f'{Fore.LIGHTYELLOW_EX}Potential SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(filteredIpv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.) {Fore.RESET}')
            report.append(f'Potential SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(filteredIpv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.)')
    else:

         #------------------------ If we get no IP addresses from the received from field, we will try to get the IP Address from the "Authentication-Results-Original" Field and do diverse lookups with it. ------------------------#
        
        # Get the content of the "Authentication-Results-Origin" Field and extract the IPv4 Address which is always after the string "sender IP is "
        if isinstance(content['Authentication-Results-Original'], str):
        
            authResultsOrigin = re.findall(r'sender IP is ([\d.]+)', content['Authentication-Results-Original'], re.IGNORECASE)
            if authResultsOrigin:
                ipv4 = authResultsOrigin
                authResultOrigIP = [ip for ip in ipv4 if ip != '127.0.0.1']
                #print(''.join(authResultIP))           

            # doing a reverse lookup for the authResultOrigIP and getting the domain name
                try:
                    authResultOrigDomain = dns.resolver.resolve(dns.reversename.from_address(''.join(authResultOrigIP)), 'PTR')
                    for domain in authResultOrigDomain:
                        authResultOrig = domain.to_text().lower()
                        #print(authResultDomain)

                except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer):
                    print(f'{Fore.LIGHTRED_EX}Could not resolve the Domain Name.{Fore.RESET}')
                    report.append(f'Could not resolve the Domain Name.')      

                # Remove the subdomain from the domain name
                tmp = authResultOrig.split('.')
                authResultFullDomain = '.'.join(tmp[-3:-1])

                # Get the MX Records of authResultFullDomain
                try:
                    authResultMx = dns.resolver.resolve(authResultFullDomain, 'MX')
                    for servers in authResultMx:
                        mxAuthResult.append(servers.exchange.to_text().lower())
                
                except dns.resolver.LifetimeTimeout:
                    print(f'{Fore.LIGHTRED_EX}Could not resolve the MX Record.{Fore.RESET}')
                    report.append(f'Could not resolve the MX Record.')

                
                # Resolving the A Records from mxAuthResult
                for n in mxAuthResult:
                    aRecordsOfMxAuthResult.append(resolveIP(n))
                
                #print(aRecordsOfMxAuthResult)
                #print(aRecordsOfMx, mxAuthResult)
                # If one of the values of mxAuthResults is in the mx list, then there is no spoofing.
                if any(x in aRecordsOfMxAuthResult for x in aRecordsOfMx):
                    print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
                    report.append(f'No Mismatch detected.')
                    #print(aRecordsOfMxAuthResult[0])
                
                else:
                    print(f'{indent}{Fore.LIGHTYELLOW_EX}No IPv4 Address detected in "FROM" Field. Doing additional checks...{Fore.RESET}')
                    report.append(f'{indent}No IPv4 Address detected in "FROM" Field. Doing additional checks...')
                    # If there is no value matching, then we need to retrieve the spf records of mxAuthResults. Extract the values between the quotes.
                    txtRecords = []
                    try:
                        authResultSpf = dns.resolver.resolve(authResultFullDomain, 'TXT')
                        for spf in authResultSpf:
                            authResultSpf = spf.to_text().lower()
                            txtRecords.append(re.findall(r'"(.*?)"', authResultSpf))
                            
                    except dns.resolver.LifetimeTimeout:
                        print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record.{Fore.RESET}')
                        report.append(f'{indent}Could not resolve the SPF Record.')
                    

                    # get the subnets from the txtRecords
                    subnetsTmp = []
                    for txt in txtRecords:
                        for subnet in txt:
                            # Extract the subnets from the txtRecords
                            subnetsTmp.append(re.findall(r'ip4:(.*)', subnet))


                    # if the list subnetsTmp does not contain something with "ip4" (most of cases), then we can continue with the check. If it is empty, then we need to do a lookup with the "include" values from the txtRecords. 
                    if any('ip4:' in subnetss for sublist in subnetsTmp for subnetss in sublist):
                        # extract the subnets from the list and put them in a new list
                        subnets = []
                        for subnet in subnetsTmp:
                            for x in subnet:
                                substrings = x.split(' ')
                                subnets.extend(s for s in substrings if s.startswith('ip4:'))


                        # convert the subnets to ipaddress objects
                        ipSubnets = []
                        for subnet in subnets:
                            subnet = subnet.replace('ip4:', '') # Remove 'ip4:' prefix
                            networks = subnet.split(' ') # Split the string into individual networks
                            for network in networks:
                                if '/' in network: # Ignore non-IP strings like '-all'
                                    ipSubnets.append(ipaddress.ip_network(network, strict=False))

        
                        # if the value of AuthResultOrigIP is in one of the subnets, then there is no spoofing. 
                        if any(ipaddress.ip_address(authResultOrigIP[0]) in subnet for subnet in ipSubnets):
                            print(f'{Fore.LIGHTGREEN_EX}{indent}→ No Mismatch detected.{Fore.RESET}')
                            report.append(f'\n{indent}→ No Mismatch detected.')
                        else:
                            print(f'{Fore.LIGHTRED_EX}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({" ".join([" ".join(t) for t in txtRecords])}){Fore.RESET}')
                            report.append(f'\n{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({" ".join([" ".join(t) for t in txtRecords])})')

                    elif not any(subnet for subnet in subnetsTmp): #if subnetTmp is empty, then we can try to get the "include" values from the txtRecords and do a lookup with them.
                        includeTmp = []
                        for txt in txtRecords:
                            for include in txt:
                                includeTmp.append(re.findall(r'include:(.*)', include))
                        
                        includeTmp = [x for x in includeTmp if x]
                        
                        # Extract value of includeTmp. This shit hurts.
                        extractionIncludeValue = [x for sublist in includeTmp for x in sublist]
                        
                        extractionIncludeValue = [mechanism for string in extractionIncludeValue for mechanism in string.split()] #split this shit               
                        extractionIncludeValue = [mechanism for mechanism in extractionIncludeValue if mechanism not in ["~all", "-all"]] # Remove "~all" and "-all" from extractionIncludeValue

                        txtRecordsOfInclude = []
                        for include in extractionIncludeValue:
                            try:
                                spfResultsInclude = dns.resolver.resolve(include, 'TXT')
                                for spfInclude in spfResultsInclude:
                                    spfResultsInclude = spfInclude.to_text().lower()
                                    txtRecordsOfInclude.append(re.findall(r'"(.*?)"', spfResultsInclude))
                            except dns.resolver.LifetimeTimeout:
                                print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record.{Fore.RESET}') 
                                report.append('Could not resolve the SPF Record.')
                        
                        # Now this shit gets funny
                        extractionSecondLevel = [y for subsublist in txtRecordsOfInclude for y in subsublist]

                        extractionSecondLevel = [technique for idontknow in extractionSecondLevel for technique in idontknow.split()]
                        extractionSecondLevel = [technique for technique in extractionSecondLevel if technique not in['~all', '-all']]
                        extractionSecondLevel = [technique for technique in extractionSecondLevel if technique != 'v=spf1']

                        # Extract the domain from the include mechanism
                        includeDomains = [mechanism.split(':')[1] for mechanism in extractionSecondLevel if mechanism.startswith('include:')]

                        txtRecordOfIncludeSecond = [] 
                        for domain in includeDomains:
                            try: 
                                resultsOfInclude = dns.resolver.resolve(domain, 'TXT')
                                for p in resultsOfInclude:
                                    includeResults = p.to_text().lower()
                                    txtRecordOfIncludeSecond.append(re.findall(r'"(.*?)"', includeResults))
                            except dns.resolver.LifetimeTimeout:
                                print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record.{Fore.RESET}')  
                                report.append('Could not resolve the SPF Record.')

                        
                        subnetsOfInclude = []
                        for b in txtRecordOfIncludeSecond:
                            for h in b:
                                subnetsOfInclude.append(re.findall(r'ip4:(.*)', h))
                        
                        if any('ip4:' in subnet for sublist in subnetsOfInclude for subnet in sublist):
                            print(f'{Fore.LIGHTYELLOW_EX}{indent}{indent}Getting deeper into the SPF Records...{Fore.RESET}')
                            report.append(f'\n{indent}{indent}Getting deeper into the SPF Records...')
                            # extract the subnets from the list and put them in a new list
                            subnets = []
                            for subnet in subnetsOfInclude:
                                for x in subnet:
                                    substrings = x.split(' ')
                                    subnets.extend(s for s in substrings if s.startswith('ip4:'))

                            # convert the subnets to ipaddress objects
                            ipSubnets = []
                            for subnet in subnets:
                                subnet = subnet.replace('ip4:', '') # Remove 'ip4:' prefix
                                networks = subnet.split(' ')
                                for network in networks:
                                    if '/' in network:
                                        ipSubnets.append(ipaddress.ip_network(network, strict=False))

                            if any(ipaddress.ip_address(authResultOrigIP[0]) in subnet for subnet in ipSubnets):
                                print(f'{Fore.LIGHTGREEN_EX}{indent}{indent}→ No Mismatch detected.{Fore.RESET}')
                                report.append(f'\n{indent}{indent}→ No Mismatch detected.')
                            else:
                                print(f'{Fore.LIGHTRED_EX}{indent}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets}){Fore.RESET}')
                                report.append(f'\n{indent}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets})')

                    else:
                        print(f'{Fore.LIGHTRED_EX}{indent}{indent}→ Could not detect SPF Record. Manual Reviewing required.{Fore.RESET}')
                        report.append(f'{indent}{indent}→ Could not detect SPF Record. Manual Reviewing required.')

        else:
            print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

    #------------------------Check for Field Mismatches------------------------#

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for Field Mismatches...{Fore.RESET}')
    report.append('\nChecking for Field Mismatches...\n')

    
    if fromMatch.group(1) is not None and content['reply-to'] is not None:
       
        print(f'{Fore.LIGHTGREEN_EX}Reply-To Field detected !{Fore.RESET}')
        report.append('Reply-To Field detected !')
        
        if formatReplyTo == False:
            if content['from'] != content['reply-to']:
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})')
            
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                report.append(f'{indent}→ No "FROM - REPLY-TO" Mismatch detected.')

        elif formatReplyTo == True:
            if fromMatch.group(1) != replyTo.group(1):
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})')
            
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                report.append(f'{indent}→ No "FROM - REPLY-TO" Mismatch detected.')

    else:
        print(f'{Fore.WHITE}No Reply-To Field detected. Skipping...{Fore.RESET}')
        report.append('No Reply-To Field detected. Skipping...')

    if fromMatch.group(1) is not None and content['return-path'] is not None:
      
        print(f'{Fore.LIGHTGREEN_EX}Return-Path Field detected !{Fore.RESET}')
        report.append('\nReturn-Path Field detected !')
      
        if formatReturnPath == False:
            if fromMatch.group(1) != content['return-path']:
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})')

            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - RETURN-PATH" Mismatch detected.{Fore.RESET}')
                report.append(f'\n{indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

        elif formatReturnPath == True:
            if fromMatch.group(1) != returnToPath.group(1):
                print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)}){Fore.RESET}')
                report.append(f'\n{indent}→ Suspicous activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})')
            
            else:
                print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - RETURN-PATH" Mismatch detected.{Fore.RESET}')
                report.append(f'\n{indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

    else:
        print(f'{Fore.WHITE}No Return-Path Field detected. Skipping...{Fore.RESET}')
        report.append('No Return-Path Field detected. Skipping...')
       
    #------------------------Check with VirusTotal------------------------#

    print(f'\n{Fore.LIGHTYELLOW_EX}Note: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}')

    print(f'{Fore.LIGHTMAGENTA_EX}Checking with VirusTotal...{Fore.RESET}')
    report.append('\n\nChecking with VirusTotal...\n')

    if filteredIpv4:
        # If you got an VT API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
        #os.system(f'curl -s -X GET --header "x-apikey: <Your API KEY>" "https://www.virustotal.com/api/v3/ip_addresses/{ipv4[0]}" > vt.json')
        
        print(f'Detections: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection{Fore.RESET}')
        print(f'Relations: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations{Fore.RESET}')
        print(f'Graph: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph{Fore.RESET}')
        print(f'Network Traffic: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic{Fore.RESET}')
        print(f'WHOIS: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois{Fore.RESET}')
        print(f'Comments: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments{Fore.RESET}')
        print(f'Votes: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes{Fore.RESET}')

        report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection\n')
        report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations\n')
        report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph\n')
        report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic\n')
        report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois\n')
        report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments\n')
        report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes\n')


    elif authResultOrigIP:
        print(f'Detections: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection{Fore.RESET}')
        print(f'Relations: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations{Fore.RESET}')
        print(f'Graph: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph{Fore.RESET}')
        print(f'Network Traffic: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic{Fore.RESET}')
        print(f'WHOIS: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois{Fore.RESET}')
        print(f'Comments: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments{Fore.RESET}')
        print(f'Votes: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes{Fore.RESET}')

        report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection\n')
        report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations\n')
        report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph\n')
        report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic\n')
        report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois\n')
        report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments\n')
        report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes\n')



    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
        report.append(f'Could not detect SMTP Server. Manual reviewing required.')

    #------------------------Check with AbuseIPDB------------------------#

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with AbuseIPDB...{Fore.RESET}')
    report.append('\nChecking with AbuseIPDB...\n')

    if filteredIpv4:
        # If you got an AbuseIPDB API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
        #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://api.abuseipdb.com/api/v2/check?ipAddress={ipv4[0]}" > abuseipdb.json')
        print(f'AbuseIPDB: {Fore.LIGHTGREEN_EX}https://www.abuseipdb.com/check/{filteredIpv4[0]}{Fore.RESET}')
        report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{filteredIpv4[0]}')
        
    elif authResultOrigIP:
        print(f'AbuseIPDB: {Fore.LIGHTGREEN_EX}https://www.abuseipdb.com/check/{authResultOrigIP[0]}{Fore.RESET}')
        report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{authResultOrigIP[0]}')
    
    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
        report.append(f'Could not detect SMTP Server. Manual reviewing required.')

    #------------------------Check with IPQualityScore------------------------#

    print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with IPQualityScore...{Fore.RESET}')
    report.append('\n\nChecking with IPQualityScore...\n')

    if filteredIpv4:
        # If you got an IPQualityScore API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
        #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://www.ipqualityscore.com/api/json/ip/<Your API KEY>/{ipv4[0]}" > ipqualityscore.json')
        print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}{Fore.RESET}')
        report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}')

    elif authResultOrigIP:
        print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}{Fore.RESET}')
        report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}')

    else:
        print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
        report.append(f'Could not detect SMTP Server. Manual reviewing required.')
    
    return ''.join(report)


   #------------------------Check if attachement is malicious or not------------------------#

def check_attachment(attachment):
    result = []

    print(f'\n\n{Fore.LIGHTBLUE_EX}Checking the attachment...{Fore.RESET}')
    result.append('\n\nChecking the attachment...\n')
    
    sha256 = hashlib.sha256()
    BUFFER = 65536
    
    with open(attachment, 'rb') as file:
        while True:
            data = file.read(BUFFER)
            if not data:
                break
            
            sha256.update(data)

    print(f'{indent}--> Link: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection{Fore.RESET}')
    result.append(f'--> Link: https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection')

    return '\n'.join(result)

     

def checkForUpdates(): 
    try:
        response = requests.get('https://api.github.com/repos/B0lg0r0v/Elyzer/releases/latest')
    except requests.exceptions.ConnectionError:
        print(f'{Fore.RED}No internet connection.{Fore.RESET}')
        exit()    
    
    latestRelease = json.loads(response.text)

    if 'tag_name' in latestRelease:
        latestVersion = latestRelease['tag_name'].lower()

        match = re.search(r'v\d+\.\d\.\d+', latestVersion) #Extract only the version number
        if match:
            latestVersion = match.group(0)

        if CURRENT_VERSION != latestVersion:
            if latestVersion > CURRENT_VERSION:
                print(f'A new version ({latestVersion}) is available. Please download it from the release section on GitHub.{Fore.RESET}')
                return True
            elif latestVersion == CURRENT_VERSION:
                pass
                return False
            elif latestVersion < CURRENT_VERSION:
                pass
                return False    
    
 
if __name__ == '__main__':

    print(r"""
          
   ____ ____  __ ____   ____ ___ 
  / __// /\ \/ //_  /  / __// _ \
 / _/ / /__\  /  / /_ / _/ / , _/
/___//____//_/  /___//___//_/|_| v0.3.3
                                  

    Author: B0lg0r0v
    https://arthurminasyan.com

    """)
    print("\n")

    colorama_init() #initialize colorama
    indent = ' ' * 3
    CURRENT_VERSION = 'v0.3.3'
    savings = []

    checkForUpdates()

    parser = ArgumentParser() #Create the Parser.
    parser.add_argument('-f', '--file', help='Give the E-Mail Header as a file.', required=True)
    parser.add_argument('-v', '--version', action='version', version=f'Elyzer {CURRENT_VERSION}')
    parser.add_argument('-a', '--attachement', help='Check if the file is malicious.')
    args = parser.parse_args() #initialize the Parser.

    

    if args.file is not None:  
        print(f'{Fore.YELLOW}E-Mail Header Analysis complete{Fore.RESET}')

        if args.attachement:
            with open(f'elyzer_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt', 'w', encoding='UTF-8') as report:
                report.write(f'Elyzer {CURRENT_VERSION}\n' + 'Author: B0lg0r0v\n' + 'https://arthurminasyan.com\n\n' +  generalInformation(args.file) + 
                            '\n' + routing(args.file) + '\n' + securityInformations(args.file) + 
                            '\n' + envelope(args.file) + '\n' + spoofing(args.file) + '\n' + check_attachment(args.attachement)) 
            
        
        else:
            with open(f'elyzer_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt', 'w', encoding='UTF-8') as report:
                report.write(f'Elyzer {CURRENT_VERSION}\n' + 'Author: B0lg0r0v\n' + 'https://arthurminasyan.com\n\n' +  generalInformation(args.file) + 
                            '\n' + routing(args.file) + '\n' + securityInformations(args.file) + 
                            '\n' + envelope(args.file) + '\n' + spoofing(args.file))
        
        print(f'\n\n\n{Fore.GREEN}-----> Report saved as "elyzer_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt"{Fore.RESET}')

    else:
        parser.error('E-Mail Header is required.')