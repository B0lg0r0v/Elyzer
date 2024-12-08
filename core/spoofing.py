import os
import re
import sys
import requests
import ipaddress
import dns.resolver
from core.utils import Utils
from core.colors import Colors
from email.parser import BytesParser






class Spoofing:

    def __init__(self, header):
        self.eHeader = header
        self.colors = Colors()
        self.utils = Utils(self.eHeader)
        self.resolveIP = self.utils.resolveIP
        self.indent = "    "
        self.resolver = dns.resolver.Resolver()
        self.api_key_driftnet = os.environ['DRIFTNET-API'] # Get your API key here: https://driftnet.io

    
    def get_vt_data(self, domain):
        url = f"{self.base_url}/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        reponse = requests.get(url, headers=headers)
        if reponse.status_code == 200:
            data = reponse.json()
            return self.parse_vt_data(data)
        
        else:
            print(self.colors.red(f"Error: {reponse.status_code} - {reponse.text}"))
            return None

    
    def parse_vt_data(self, data):
        dns_records = {
            'A': [],
            'MX': [],
            'TXT': [],
            'NS': []
        }
        
        attributes = data.get('data', {}).get('attributes', {})
        last_dns_records = attributes.get('last_dns_records', [])

        for record in last_dns_records:
            record_type = record.get('type')
            if record_type in dns_records:
                dns_records[record_type].append(record)

        return dns_records

    
    #--------------------- This is the "all checks" function. It performs actively DNS resolution. ---------------------#

    def spoofing_all_checks(self):

        report = []

        try:
            with open(self.eHeader, 'r', encoding='UTF-8') as header:
                content = BytesParser().parsebytes(header.read().encode('UTF-8'))
        except FileNotFoundError:
            #print(f'{Fore.RED}File not found.{Fore.RESET}')
            self.colors.red("File not found.")
            sys.exit(1)

        #print(f'\n{Fore.LIGHTBLUE_EX}Spoofing Check: {Fore.RESET}')
        print(self.colors.light_blue("\nSpoofing Check:"))
        report.append(f'\nSpoofing Check:\n')

        #------------------------Regex and Field definitions------------------------#

        x = next(iter(reversed(self.utils.getReceivedFields())), None)
        if x is not None:
            ipv4 = re.findall(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]', x, re.IGNORECASE)
            #ipv6 = re.findall(r'[\[\(]([A-Fa-f0-9:]+)[\]\)]', x, re.IGNORECASE)
        else:
            ipv4 = []
            print(self.colors.red("No 'Received' fields found in the email header."))

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
        messageIDMx = []
        aRecordsOfMx = []

        mxAuthResult = []
        aRecordsOfMxAuthResult = []
        authResultOrigIP = None

        # Getting the Domain Name from the "From" Field
        if fromMatch is not None:
            fromEmailDomain = fromMatch.group(1).split('@')[1]
        else:
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.\n')

        # Getting the MX Records from the Domain Name
        try:
            getMx = self.resolver.resolve(fromEmailDomain, 'MX')
            for servers in getMx:
                mx.append(servers.exchange.to_text().lower())

        except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.YXDOMAIN,dns.resolver.NoNameservers):
            print(self.colors.red("Could not resolve the MX Record."))
        # Resolving the A Records from the MX Records  
        for servers in mx:
            aRecordsOfMx.append(self.resolveIP(servers))
                    

        print(self.colors.magenta("\nChecking for SMTP Server Mismatch..."))
        report.append('\nChecking for SMTP Server Mismatch...\n')  

        if filteredIpv4:
            if filteredIpv4[0] in aRecordsOfMx:
                #print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
                print(self.colors.green("No Mismatch detected."))
                report.append(f'No Mismatch detected.')
            else:
                print(self.colors.yellow(f'{self.indent}→ Potential SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(filteredIpv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.)'))
                report.append(f'{self.indent}→ Potential SMTP Server Mismatch detected. Sender SMTP Server is "{fromEmailDomain} [{"".join(filteredIpv4[0])}]" and should be "{fromEmailDomain} [{", ".join(aRecordsOfMx)}]" <- (current MX Record(s) for this domain.)')
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
                        authResultOrigDomain = self.resolver.resolve(dns.reversename.from_address(''.join(authResultOrigIP)), 'PTR')
                        for domain in authResultOrigDomain:
                            authResultOrig = domain.to_text().lower()
                            #print(authResultDomain)

                    except (dns.resolver.LifetimeTimeout, dns.resolver.NoAnswer):
                        #print(f'{Fore.LIGHTRED_EX}Could not resolve the Domain Name.{Fore.RESET}')
                        print(self.colors.red("Could not resolve the Domain Name."))
                        report.append(f'Could not resolve the Domain Name.')      

                    # Remove the subdomain from the domain name
                    tmp = authResultOrig.split('.')
                    authResultFullDomain = '.'.join(tmp[-3:-1])

                    # Get the MX Records of authResultFullDomain
                    try:
                        authResultMx = self.resolver.resolve(authResultFullDomain, 'MX')
                        for servers in authResultMx:
                            mxAuthResult.append(servers.exchange.to_text().lower())
                    
                    except dns.resolver.LifetimeTimeout:
                        #print(f'{Fore.LIGHTRED_EX}Could not resolve the MX Record.{Fore.RESET}')
                        print(self.colors.red("Could not resolve the MX Record."))
                        report.append(f'Could not resolve the MX Record.')

                    
                    # Resolving the A Records from mxAuthResult
                    for n in mxAuthResult:
                        aRecordsOfMxAuthResult.append(self.resolveIP(n))
                    
                    #print(aRecordsOfMxAuthResult)
                    #print(aRecordsOfMx, mxAuthResult)
                    # If one of the values of mxAuthResults is in the mx list, then there is no spoofing.
                    if any(x in aRecordsOfMxAuthResult for x in aRecordsOfMx):
                        #print(f'{Fore.LIGHTGREEN_EX}No Mismatch detected.{Fore.RESET}')
                        print(self.colors.green("No Mismatch detected."))
                        report.append(f'No Mismatch detected.')
                        #print(aRecordsOfMxAuthResult[0])
                    
                    else:
                        print(self.colors.yellow(f'{self.indent}No IPv4 Address detected in "FROM" Field. Doing additional checks...'))
                        #report.append(f'{indent}No IPv4 Address detected in "FROM" Field. Doing additional checks...')
                        report.append(f'{self.indent}No IPv4 Address detected in "FROM" Field. Doing additional checks...')
                        # If there is no value matching, then we need to retrieve the spf records of mxAuthResults. Extract the values between the quotes.
                        txtRecords = []
                        try:
                            authResultSpf = self.resolver.resolve(authResultFullDomain, 'TXT')
                            for spf in authResultSpf:
                                authResultSpf = spf.to_text().lower()
                                txtRecords.append(re.findall(r'"(.*?)"', authResultSpf))
                                
                        except dns.resolver.LifetimeTimeout:
                            #print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record.{Fore.RESET}')
                            print(self.colors.red("Could not resolve the SPF Record."))
                            report.append(f'{self.indent}Could not resolve the SPF Record.')

                        
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

                            if any(ipaddress.ip_address(authResultOrigIP[0]) in subnet for subnet in ipSubnets):
                                print(self.colors.green(f'{self.indent}{self.indent}→ No Mismatch detected.'))
                                report.append(f'\n{self.indent}{self.indent}→ No Mismatch detected.')
                            else:
                                print(self.colors.light_yellow(f'{self.indent}{self.indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets})'))
                                report.append(f'\n{self.indent}{self.indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets})')


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
                                    spfResultsInclude = self.resolver.resolve(include, 'TXT')
                                    for spfInclude in spfResultsInclude:
                                        spfResultsInclude = spfInclude.to_text().lower()
                                        txtRecordsOfInclude.append(re.findall(r'"(.*?)"', spfResultsInclude))
                                except dns.resolver.LifetimeTimeout:
                                    #print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record.{Fore.RESET}') 
                                    print(self.colors.red("Could not resolve the SPF Record."))
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
                                    resultsOfInclude = self.resolver.resolve(domain, 'TXT')
                                    for p in resultsOfInclude:
                                        includeResults = p.to_text().lower()
                                        txtRecordOfIncludeSecond.append(re.findall(r'"(.*?)"', includeResults))
                                except dns.resolver.LifetimeTimeout:
                                    #print(f'{Fore.LIGHTRED_EX}Could not resolve the SPF Record.{Fore.RESET}')  
                                    print(self.colors.red("Could not resolve the SPF Record."))
                                    report.append('Could not resolve the SPF Record.')

                            
                            subnetsOfInclude = []
                            for b in txtRecordOfIncludeSecond:
                                for h in b:
                                    subnetsOfInclude.append(re.findall(r'ip4:(.*)', h))
                            
                            if any('ip4:' in subnet for sublist in subnetsOfInclude for subnet in sublist):
                                #print(f'{Fore.LIGHTYELLOW_EX}{indent}{indent}Getting deeper into the SPF Records...{Fore.RESET}')
                                print(self.colors.yellow(f'{self.indent}{self.indent}Getting deeper into the SPF Records...'))
                                report.append(f'\n{self.indent}{self.indent}Getting deeper into the SPF Records...')
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
                                    #print(f'{Fore.LIGHTGREEN_EX}{indent}{indent}→ No Mismatch detected.{Fore.RESET}')
                                    print(self.colors.green(f'{self.indent}{self.indent}→ No Mismatch detected.'))
                                    report.append(f'\n{self.indent}{self.indent}→ No Mismatch detected.')
                                else:
                                    #print(f'{Fore.LIGHTRED_EX}{indent}{indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets}){Fore.RESET}')
                                    print(self.colors.red(f'{self.indent}{self.indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets})'))
                                    report.append(f'\n{self.indent}{self.indent}→ Potential Mismatch detected: Authentication-Results-Original ({authResultOrigIP[0]}) NOT IN SPF Record ({subnets})')

                        else:
                            #print(f'{Fore.LIGHTRED_EX}{indent}{indent}→ Could not detect SPF Record. Manual Reviewing required.{Fore.RESET}')
                            print(self.colors.red(f'{self.indent}{self.indent}→ Could not detect SPF Record. Manual Reviewing required.'))
                            report.append(f'\n{self.indent}{self.indent}→ Could not detect SPF Record. Manual Reviewing required.')

            else:
                #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
                print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
                report.append(f'Could not detect SMTP Server. Manual reviewing required.\n')

        #------------------------Check for Field Mismatches------------------------#

        #print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for Field Mismatches...{Fore.RESET}')
        print(self.colors.magenta("\nChecking for Field Mismatches..."))
        report.append('\nChecking for Field Mismatches...\n')

        if content['message-id'] is not None:
            #print(f'{Fore.LIGHTGREEN_EX}Message-ID Field detected !{Fore.RESET}')
            print(self.colors.green("Message-ID Field detected !"))
            report.append('Message-ID Field detected !\n')
            # Get the domain name between the "<>" brackets and split it at the "@" sign
            messageIDDomain = content['message-id'].split('@')[1].split('>')[0]
            #print(messageIDDomain)
            if fromEmailDomain.strip().lower() != messageIDDomain.strip().lower():
                #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: Message-ID Domain "{messageIDDomain}" NOT EQUAL "FROM" Domain "{fromEmailDomain}"{Fore.RESET}')
                print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: Message-ID Domain "{messageIDDomain}" NOT EQUAL "FROM" Domain "{fromEmailDomain}"'))
                report.append(f'{self.indent}→ Suspicious activity detected: Message-ID Domain ({messageIDDomain}) NOT EQUAL "FROM" Domain ({fromEmailDomain})\n')
            else:
                #print(f'{Fore.LIGHTGREEN_EX}{indent}→ No Mismatch detected.{Fore.RESET}')
                print(self.colors.green(f'{self.indent}→ No Mismatch detected.'))
                report.append(f'{self.indent}→ No Mismatch detected.\n') 
        
        else:
            #print(f'{Fore.WHITE}No Message-ID Field detected. Skipping...{Fore.RESET}')
            print(self.colors.white("No Message-ID Field detected. Skipping..."))
            report.append('No Message-ID Field detected. Skipping...\n')

        
        if fromMatch.group(1) is not None and content['reply-to'] is not None:
        
            #print(f'{Fore.LIGHTGREEN_EX}Reply-To Field detected !{Fore.RESET}')
            print(self.colors.green("Reply-To Field detected !"))
            report.append('Reply-To Field detected !')
            
            if formatReplyTo == False:
                if content['from'].strip().lower() != content['reply-to'].strip().lower():
                    #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]}){Fore.RESET}')
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})')
                
                else:
                    #print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                    print(self.colors.green(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.'))
                    report.append(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.')

            elif formatReplyTo == True:
                if fromMatch.group(1).strip().lower() != replyTo.group(1).strip().lower():
                    #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)}){Fore.RESET}')
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})')
                
                else:
                    #print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                    print(self.colors.green(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.'))
                    report.append(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.')

        else:
            #print(f'{Fore.WHITE}No Reply-To Field detected. Skipping...{Fore.RESET}')
            print(self.colors.white("No Reply-To Field detected. Skipping..."))
            report.append('No Reply-To Field detected. Skipping...\n')

        if fromMatch.group(1) is not None and content['return-path'] is not None:
        
            #print(f'{Fore.LIGHTGREEN_EX}Return-Path Field detected !{Fore.RESET}')
            print(self.colors.green("Return-Path Field detected !"))
            report.append('\nReturn-Path Field detected !')
        
            if formatReturnPath == False:
                if fromMatch.group(1).strip().lower() != content['return-path'].strip().lower():
                    #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]}){Fore.RESET}')
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})')

                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.'))
                    report.append(f'\n{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

            elif formatReturnPath == True:
                if fromMatch.group(1).strip().lower() != returnToPath.group(1).strip().lower():
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})')
                
                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.'))
                    report.append(f'\n{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

        else:
            print(self.colors.white("No Return-Path Field detected. Skipping..."))
            report.append('No Return-Path Field detected. Skipping...')
        
        #------------------------Check with VirusTotal------------------------#

        #print(f'\n{Fore.LIGHTYELLOW_EX}Note: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}')
        print(self.colors.yellow("\nNote: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code."))

        print(self.colors.magenta("\nChecking with VirusTotal..."))
        report.append('\n\nChecking with VirusTotal...\n')

        if filteredIpv4:
            # If you got an VT API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "x-apikey: <Your API KEY>" "https://www.virustotal.com/api/v3/ip_addresses/{ipv4[0]}" > vt.json')
            
            print(f'Detections: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection")}')
            print(f'Relations: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations")}')
            print(f'Graph: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph")}')
            print(f'Network Traffic: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic")}')
            print(f'WHOIS: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois")}')
            print(f'Comments: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments")}')
            print(f'Votes: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes")}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes\n')


        elif authResultOrigIP:
            print(f'Detections: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection")}'),
            print(f'Relations: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations")}')
            print(f'Graph: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph")}')
            print(f'Network Traffic: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic")}')
            print(f'WHOIS: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois")}')
            print(f'Comments: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments")}')
            print(f'Votes: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes")}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes\n')



        else:
            #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

        #------------------------Check with AbuseIPDB------------------------#

        print(self.colors.magenta("\nChecking with AbuseIPDB..."))
        report.append('\nChecking with AbuseIPDB...\n')

        if filteredIpv4:
            # If you got an AbuseIPDB API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://api.abuseipdb.com/api/v2/check?ipAddress={ipv4[0]}" > abuseipdb.json')
            print(f'AbuseIPDB: {self.colors.green(f"https://www.abuseipdb.com/check/{filteredIpv4[0]}")}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{filteredIpv4[0]}')
            
        elif authResultOrigIP:
            print(f'AbuseIPDB: {self.colors.green(f"https://www.abuseipdb.com/check/{authResultOrigIP[0]}")}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{authResultOrigIP[0]}')
        
        else:
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

        #------------------------Check with IPQualityScore------------------------#

        #print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with IPQualityScore...{Fore.RESET}')
        print(self.colors.magenta("\nChecking with IPQualityScore..."))
        report.append('\n\nChecking with IPQualityScore...\n')

        if filteredIpv4:
            # If you got an IPQualityScore API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://www.ipqualityscore.com/api/json/ip/<Your API KEY>/{ipv4[0]}" > ipqualityscore.json')
            #print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}{Fore.RESET}')
            print(f'IPQualityScore: {self.colors.green(f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}")}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}')

        elif authResultOrigIP:
            #print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}{Fore.RESET}')
            print(f'IPQualityScore: {self.colors.green(f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}")}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}')

        else:
            #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')
        
        return ''.join(report)
    

    #------------------------This part is for the passive DNS check.------------------------#

    # Function for fetching A Records via the Driftnet API
    def passive_a_records_driftnet(self, mx_server):


        a_records = []  
        url = f"https://api.driftnet.io/v1/domain/fdns?host={mx_server}"

        headers = {
            'Authorization': f'Bearer {self.api_key_driftnet}',
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:

            parsed_json = response.json()

            # First iteration is for parsing the JSON structure first
            for x in parsed_json['results']:
                # Second iteration is for getting the 'items' key
                for y in x['items']:
                    # Third iteration is for filtering the results and getting the exact host value that matches the mx_server variable
                    if y['value'] == mx_server:
                        # Fourth iteration is iterating again over the 'items' key, but this time we have filtered it and we can get the context key that equals to 'dns-a
                        for z in x['items']:
                            if z['context'] == 'dns-a':
                                a_records.append(z['value'])
            
            return a_records


        else:
            #print(self.colors.red(f"[DEBUG] Error getting A records for {mx_server}: {response.status_code}"))
            return None
            
    # Funtion for fetching MX Records via the Driftnet API
    def passive_mx_records_driftnet(self, domain):
        
        results = []
        
        try:

            url = f"https://api.driftnet.io/v1/domain/mx?host={domain}"

            headers = {
                'Authorization': f'Bearer {self.api_key_driftnet}',
                'Content-Type': 'application/json'
            }

            # Doing the actual request
            response = requests.get(url, headers=headers)
            if response.status_code == 200:

                parsed_json = response.json()

                for x in parsed_json['results']:
                    for y in x['items']:
                        if y['type'] == 'host':
                            for z in x['items']:
                                if z['context'] == 'dns-mx' and z['type'] == 'host':
                                    results.append(z['value'])
                                    

            # filtering out the duplicates from results
            return list(set(results))

        except Exception as e:
            print(self.colors.red(f"Error getting MX records for {domain}: {str(e)}"))
            return[]
            

    # Revere DNS lookup via the Driftnet API
    def passive_reverse_dns_driftnet(self, ip):
        url = f"https://api.driftnet.io/v1/domain/rdns?ip={ip}"

        headers = {
            'Authorization': f'Bearer {self.api_key_driftnet}',
            'Content-Type': 'application/json'
        }
    
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                parsed_data = self.parse_driftnet_response(response.json())
                return parsed_data['ptr_records']
            else:
                print(self.colors.red(f"Error getting reverse DNS for {ip}: {response.status_code}"))
                return []
        except Exception as e:
            print(self.colors.red(f"Error getting reverse DNS for {ip}: {str(e)}"))
            return []
        

    @staticmethod
    def parse_driftnet_response(data):
        try:
            values = []
            ptr_records = []

            for result in data.get('results', []):
                for item in result.get('items', []):
                    value = item.get('value')
                    if value:
                        values.append(value)
                        if item.get('context') == 'dns-ptr':
                            ptr_records.append(value)

            return {
                'all_values': values,
                'ptr_records': ptr_records
            }

        except KeyError as e:
            print(f"Error: Missing expected key in JSON structure: {e}")
            return {'all_values': [], 'ptr_records': []}


    def spoofing_passive_dns(self):

        report = []

        try:
            with open(self.eHeader, 'r', encoding='UTF-8') as header:
                content = BytesParser().parsebytes(header.read().encode('UTF-8'))
        except FileNotFoundError:
            self.colors.red("File not found.")
            sys.exit(1)

        print(self.colors.light_blue("\nSpoofing Check:"))
        report.append(f'\nSpoofing Check:\n')

        #------------------------Regex and Field definitions------------------------#

        x = next(iter(reversed(self.utils.getReceivedFields())), None)
        if x is not None:
            ipv4 = re.findall(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]', x, re.IGNORECASE)
            #ipv6 = re.findall(r'[\[\(]([A-Fa-f0-9:]+)[\]\)]', x, re.IGNORECASE)
        else:
            ipv4 = []
            print(self.colors.red("No 'Received' fields found in the email header."))

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
        messageIDMx = []
        aRecordsOfMx = []

        mxAuthResult = []
        aRecordsOfMxAuthResult = []
        authResultOrigIP = None

        # Getting the Domain Name from the "From" Field
        if fromMatch is not None:
            fromEmailDomain = fromMatch.group(1).split('@')[1]
        else:
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.\n')
        

        #print('Email Domain:', fromEmailDomain) # Debug statement

        DF_MX_A_RECORD = self.passive_a_records_driftnet(fromEmailDomain)
        if DF_MX_A_RECORD is None:
            print(self.colors.red("Could not retrieve data from VirusTotal."))
            return ''.join(report)

        #print('A Records:', DF_MX_A_RECORD) # Debug statement
        DF_MX_A_RECORD = list(dict.fromkeys(DF_MX_A_RECORD))

        print(self.colors.light_magenta("\nChecking for SMTP Server Mismatch..."))
        report.append(f'\nChecking for SMTP Server Mismatch...\n')

        if filteredIpv4:
            for tmp in DF_MX_A_RECORD:
                if filteredIpv4[0] in tmp:
                    print(self.colors.green(f'{self.indent}→ No Mismatch detected.'))
                    report.append(f'{self.indent}→ No Mismatch detected.')
                else:
                    print(self.colors.yellow(f'{self.indent}→ Potential SMTP Server Mismatch detected. Sender SMTP Server is {fromEmailDomain} [{filteredIpv4[0]}] and should be {tmp} <- (current MX Record(s) for this domain)'))
                    report.append(f'{self.indent}→ Suspicious activity detected: SMTP Server Mismatch detected.')

        else:
            if isinstance(content['Authentication-Results-Original'], str):
                authResultsOrigin = re.findall(r'sender IP is ([\d.]+)', content['Authentication-Results-Original'], re.IGNORECASE)
                if authResultsOrigin:
                    ipv4 = authResultsOrigin
                    authResultOrigIP = [ip for ip in ipv4 if ip != '127.0.0.1']

            else:
                print(self.colors.white("No 'Authentication-Results-Original' Header found. Manual reviewing required."))

            #print(authResultOrigIP) # Debug statement
            if authResultOrigIP:
                try:
                    for domain in authResultOrigIP:
                        associated_domain = self.passive_reverse_dns_driftnet(domain)
                        # filtering duplicates
                        associated_domain = list(dict.fromkeys(associated_domain))
                        #print(associated_domain) # Debug statement
                

                    for subdomain in associated_domain:
                        tmp = subdomain.split('.')
                        authResultFullDomain = '.'.join(tmp[-2:])
                        #print(authResultFullDomain) # Debug statement

                        mx_records_from_df = self.passive_mx_records_driftnet(authResultFullDomain)
                        #print(mx_records_from_df) # Debug statement

                        for x in mx_records_from_df:
                            aRecordsOfMxAuthResult.append(self.passive_a_records_driftnet(x))
                            #print(aRecordsOfMxAuthResult) # Debug statement

                    # Flattening the list
                    if aRecordsOfMxAuthResult:
                        aRecordsOfMxAuthResult = [item for sublist in aRecordsOfMxAuthResult if sublist is not None for item in sublist]
                    
                    #print(aRecordsOfMxAuthResult) # Debug statement
                    if any(x in aRecordsOfMxAuthResult for x in DF_MX_A_RECORD):
                        print(self.colors.green(f'{self.indent}→ No Mismatch detected.'))
                        report.append(f'{self.indent}→ No Mismatch detected.')

                    else:
                        print(self.colors.light_yellow(f'{self.indent}Could not compare values. Manual reviewing required...'))
                        report.append(f'{self.indent}Could not compare values. Manual reviewing required...')

                except Exception as e:
                    print(self.colors.red(f"An error occurred while querying the API: {str(e)}"))

            else:
                pass

        #------------------------Check for Field Mismatches------------------------#

        print(self.colors.magenta("\nChecking for Field Mismatches..."))
        report.append('\nChecking for Field Mismatches...\n')

        if content['message-id'] is not None:
            print(self.colors.green("Message-ID Field detected !"))
            report.append('Message-ID Field detected !\n')
            # Get the domain name between the "<>" brackets and split it at the "@" sign
            messageIDDomain = content['message-id'].split('@')[1].split('>')[0]
            #print(messageIDDomain)
            if fromEmailDomain.strip().lower() != messageIDDomain.strip().lower():
                print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: Message-ID Domain "{messageIDDomain}" NOT EQUAL "FROM" Domain "{fromEmailDomain}"'))
                report.append(f'{self.indent}→ Suspicious activity detected: Message-ID Domain ({messageIDDomain}) NOT EQUAL "FROM" Domain ({fromEmailDomain})\n')
            else:
                print(self.colors.green(f'{self.indent}→ No Mismatch detected.'))
                report.append(f'{self.indent}→ No Mismatch detected.\n') 
        
        else:
            print(self.colors.white("No Message-ID Field detected. Skipping..."))
            report.append('No Message-ID Field detected. Skipping...\n')

        
        if fromMatch.group(1) is not None and content['reply-to'] is not None:
        
            print(self.colors.green("Reply-To Field detected !"))
            report.append('Reply-To Field detected !')
            
            if formatReplyTo == False:
                if content['from'].strip().lower() != content['reply-to'].strip().lower():
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})')
                
                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.'))
                    report.append(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.')

            elif formatReplyTo == True:
                if fromMatch.group(1).strip().lower() != replyTo.group(1).strip().lower():
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})')
                
                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.'))
                    report.append(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.')

        else:
            print(self.colors.white("No Reply-To Field detected. Skipping..."))
            report.append('No Reply-To Field detected. Skipping...\n')

        if fromMatch.group(1) is not None and content['return-path'] is not None:
        
            print(self.colors.green("Return-Path Field detected !"))
            report.append('\nReturn-Path Field detected !')
        
            if formatReturnPath == False:
                if fromMatch.group(1).strip().lower() != content['return-path'].strip().lower():
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})')

                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.'))
                    report.append(f'\n{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

            elif formatReturnPath == True:
                if fromMatch.group(1).strip().lower() != returnToPath.group(1).strip().lower():
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})')
                
                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.'))
                    report.append(f'\n{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

        else:
            print(self.colors.white("No Return-Path Field detected. Skipping..."))
            report.append('No Return-Path Field detected. Skipping...')

         #------------------------Check with VirusTotal------------------------#

        #print(f'\n{Fore.LIGHTYELLOW_EX}Note: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}')
        print(self.colors.yellow("\nNote: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code."))

        print(self.colors.magenta("\nChecking with VirusTotal..."))
        report.append('\n\nChecking with VirusTotal...\n')

        if filteredIpv4:
            # If you got an VT API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "x-apikey: <Your API KEY>" "https://www.virustotal.com/api/v3/ip_addresses/{ipv4[0]}" > vt.json')
            
            print(f'Detections: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection")}')
            print(f'Relations: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations")}')
            print(f'Graph: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph")}')
            print(f'Network Traffic: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic")}')
            print(f'WHOIS: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois")}')
            print(f'Comments: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments")}')
            print(f'Votes: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes")}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes\n')


        elif authResultOrigIP:
            print(f'Detections: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection")}'),
            print(f'Relations: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations")}')
            print(f'Graph: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph")}')
            print(f'Network Traffic: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic")}')
            print(f'WHOIS: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois")}')
            print(f'Comments: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments")}')
            print(f'Votes: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes")}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes\n')



        else:
            #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

        #------------------------Check with AbuseIPDB------------------------#

        print(self.colors.magenta("\nChecking with AbuseIPDB..."))
        report.append('\nChecking with AbuseIPDB...\n')

        if filteredIpv4:
            # If you got an AbuseIPDB API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://api.abuseipdb.com/api/v2/check?ipAddress={ipv4[0]}" > abuseipdb.json')
            print(f'AbuseIPDB: {self.colors.green(f"https://www.abuseipdb.com/check/{filteredIpv4[0]}")}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{filteredIpv4[0]}')
            
        elif authResultOrigIP:
            print(f'AbuseIPDB: {self.colors.green(f"https://www.abuseipdb.com/check/{authResultOrigIP[0]}")}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{authResultOrigIP[0]}')
        
        else:
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

        #------------------------Check with IPQualityScore------------------------#

        #print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with IPQualityScore...{Fore.RESET}')
        print(self.colors.magenta("\nChecking with IPQualityScore..."))
        report.append('\n\nChecking with IPQualityScore...\n')

        if filteredIpv4:
            # If you got an IPQualityScore API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://www.ipqualityscore.com/api/json/ip/<Your API KEY>/{ipv4[0]}" > ipqualityscore.json')
            #print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}{Fore.RESET}')
            print(f'IPQualityScore: {self.colors.green(f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}")}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}')

        elif authResultOrigIP:
            #print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}{Fore.RESET}')
            print(f'IPQualityScore: {self.colors.green(f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}")}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}')

        else:
            #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')
        
        return ''.join(report)
    

    #------------------------This part is for the NO DNS check.------------------------#

    def spoofing_no_dns(self):

        report = []

        try:
            with open(self.eHeader, 'r', encoding='UTF-8') as header:
                content = BytesParser().parsebytes(header.read().encode('UTF-8'))
        except FileNotFoundError:
            self.colors.red("File not found.")
            sys.exit(1)

        print(self.colors.light_red("\nNo DNS resolution is performed. This heavily affects the results !"))
        report.append(f'No DNS resolution is performed. This heavily affects the results !!\n')

        print(self.colors.light_blue("\nSpoofing Check:"))
        report.append(f'\nSpoofing Check:\n')
        
        #------------------------Regex and Field definitions------------------------#

        x = next(iter(reversed(self.utils.getReceivedFields())), None)
        if x is not None:
            ipv4 = re.findall(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]', x, re.IGNORECASE)
            ipv6 = re.findall(r'[\[\(]([A-Fa-f0-9:]+)[\]\)]', x, re.IGNORECASE)

        else:
            print(self.colors.red("No 'Received' fields found in the email header."))
            ipv4 = []
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
        messageIDMx = []
        aRecordsOfMx = []

        mxAuthResult = []
        aRecordsOfMxAuthResult = []
        authResultOrigIP = None

        # Getting the Domain Name from the "From" Field
        if fromMatch is not None:
            fromEmailDomain = fromMatch.group(1).split('@')[1]
        else:
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.\n')
        

        #------------------------Check for Field Mismatches------------------------#

        #print(f'\n{Fore.LIGHTMAGENTA_EX}Checking for Field Mismatches...{Fore.RESET}')
        print(self.colors.magenta("\nChecking for Field Mismatches..."))
        report.append('\nChecking for Field Mismatches...\n')

        if content['message-id'] is not None:
            #print(f'{Fore.LIGHTGREEN_EX}Message-ID Field detected !{Fore.RESET}')
            print(self.colors.green("Message-ID Field detected !"))
            report.append('Message-ID Field detected !\n')
            # Get the domain name between the "<>" brackets and split it at the "@" sign
            messageIDDomain = content['message-id'].split('@')[1].split('>')[0]
            #print(messageIDDomain)
            if fromEmailDomain.strip().lower() != messageIDDomain.strip().lower():
                #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: Message-ID Domain "{messageIDDomain}" NOT EQUAL "FROM" Domain "{fromEmailDomain}"{Fore.RESET}')
                print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: Message-ID Domain "{messageIDDomain}" NOT EQUAL "FROM" Domain "{fromEmailDomain}"'))
                report.append(f'{self.indent}→ Suspicious activity detected: Message-ID Domain ({messageIDDomain}) NOT EQUAL "FROM" Domain ({fromEmailDomain})\n')
            else:
                #print(f'{Fore.LIGHTGREEN_EX}{indent}→ No Mismatch detected.{Fore.RESET}')
                print(self.colors.green(f'{self.indent}→ No Mismatch detected.'))
                report.append(f'{self.indent}→ No Mismatch detected.\n') 
        
        else:
            #print(f'{Fore.WHITE}No Message-ID Field detected. Skipping...{Fore.RESET}')
            print(self.colors.white("No Message-ID Field detected. Skipping..."))
            report.append('No Message-ID Field detected. Skipping...\n')

        
        if fromMatch.group(1) is not None and content['reply-to'] is not None:
        
            #print(f'{Fore.LIGHTGREEN_EX}Reply-To Field detected !{Fore.RESET}')
            print(self.colors.green("Reply-To Field detected !"))
            report.append('Reply-To Field detected !')
            
            if formatReplyTo == False:
                if content['from'].strip().lower() != content['reply-to'].strip().lower():
                    #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]}){Fore.RESET}')
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({content["reply-to"]})')
                
                else:
                    #print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                    print(self.colors.green(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.'))
                    report.append(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.')

            elif formatReplyTo == True:
                if fromMatch.group(1).strip().lower() != replyTo.group(1).strip().lower():
                    #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)}){Fore.RESET}')
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "REPLY-TO" Field ({replyTo.group(1)})')
                
                else:
                    #print(f'{Fore.LIGHTGREEN_EX}{indent}→ No "FROM - REPLY-TO" Mismatch detected.{Fore.RESET}')
                    print(self.colors.green(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.'))
                    report.append(f'{self.indent}→ No "FROM - REPLY-TO" Mismatch detected.')

        else:
            #print(f'{Fore.WHITE}No Reply-To Field detected. Skipping...{Fore.RESET}')
            print(self.colors.white("No Reply-To Field detected. Skipping..."))
            report.append('No Reply-To Field detected. Skipping...\n')

        if fromMatch.group(1) is not None and content['return-path'] is not None:
        
            #print(f'{Fore.LIGHTGREEN_EX}Return-Path Field detected !{Fore.RESET}')
            print(self.colors.green("Return-Path Field detected !"))
            report.append('\nReturn-Path Field detected !')
        
            if formatReturnPath == False:
                if fromMatch.group(1).strip().lower() != content['return-path'].strip().lower():
                    #print(f'{Fore.LIGHTYELLOW_EX}{indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]}){Fore.RESET}')
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({content["return-path"]})')

                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.'))
                    report.append(f'\n{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

            elif formatReturnPath == True:
                if fromMatch.group(1).strip().lower() != returnToPath.group(1).strip().lower():
                    print(self.colors.yellow(f'{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})'))
                    report.append(f'\n{self.indent}→ Suspicious activity detected: "FROM" Field ({fromMatch.group(1)}) NOT EQUAL "RETURN-PATH" Field ({returnToPath.group(1)})')
                
                else:
                    print(self.colors.green(f'{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.'))
                    report.append(f'\n{self.indent}→ No "FROM - RETURN-PATH" Mismatch detected.')

        else:
            print(self.colors.white("No Return-Path Field detected. Skipping..."))
            report.append('No Return-Path Field detected. Skipping...')
        
        #------------------------Check with VirusTotal------------------------#

        #print(f'\n{Fore.LIGHTYELLOW_EX}Note: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code.{Fore.RESET}')
        print(self.colors.yellow("\nNote: You can use your own VirusTotal, AbuseIPDB and IPQualityScore API Key to generate a report for the IP Address. Check the Source Code."))

        print(self.colors.magenta("Checking with VirusTotal..."))
        report.append('\n\nChecking with VirusTotal...\n')

        if filteredIpv4:
            # If you got an VT API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "x-apikey: <Your API KEY>" "https://www.virustotal.com/api/v3/ip_addresses/{ipv4[0]}" > vt.json')
            
            print(f'Detections: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection")}')
            print(f'Relations: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations")}')
            print(f'Graph: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph")}')
            print(f'Network Traffic: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic")}')
            print(f'WHOIS: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois")}')
            print(f'Comments: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments")}')
            print(f'Votes: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes")}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{filteredIpv4[0]}/votes\n')


        elif authResultOrigIP:
            print(f'Detections: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection")}'),
            print(f'Relations: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations")}')
            print(f'Graph: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph")}')
            print(f'Network Traffic: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic")}')
            print(f'WHOIS: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois")}')
            print(f'Comments: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments")}')
            print(f'Votes: {self.colors.green(f"https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes")}')

            report.append(f'Detections: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/detection\n')
            report.append(f'Relations: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/relations\n')
            report.append(f'Graph: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/graph\n')
            report.append(f'Network Traffic: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/network-traffic\n')
            report.append(f'WHOIS: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/whois\n')
            report.append(f'Comments: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/comments\n')
            report.append(f'Votes: https://www.virustotal.com/gui/ip-address/{authResultOrigIP[0]}/votes\n')



        else:
            #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

        #------------------------Check with AbuseIPDB------------------------#

        print(self.colors.magenta("\nChecking with AbuseIPDB..."))
        report.append('\nChecking with AbuseIPDB...\n')

        if filteredIpv4:
            # If you got an AbuseIPDB API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://api.abuseipdb.com/api/v2/check?ipAddress={ipv4[0]}" > abuseipdb.json')
            print(f'AbuseIPDB: {self.colors.green(f"https://www.abuseipdb.com/check/{filteredIpv4[0]}")}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{filteredIpv4[0]}')
            
        elif authResultOrigIP:
            print(f'AbuseIPDB: {self.colors.green(f"https://www.abuseipdb.com/check/{authResultOrigIP[0]}")}')
            report.append(f'AbuseIPDB: https://www.abuseipdb.com/check/{authResultOrigIP[0]}')
        
        else:
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')

        #------------------------Check with IPQualityScore------------------------#

        #print(f'\n{Fore.LIGHTMAGENTA_EX}Checking with IPQualityScore...{Fore.RESET}')
        print(self.colors.magenta("\nChecking with IPQualityScore..."))
        report.append('\n\nChecking with IPQualityScore...\n')

        if filteredIpv4:
            # If you got an IPQualityScore API Key, you can use it here. It will generate a report for the IP Address. Uncomment the line under this comment and replace <Your API KEY> with your API Key.
            #os.system(f'curl -s -X GET --header "Key: <Your API KEY>" "https://www.ipqualityscore.com/api/json/ip/<Your API KEY>/{ipv4[0]}" > ipqualityscore.json')
            #print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}{Fore.RESET}')
            print(f'IPQualityScore: {self.colors.green(f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}")}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{filteredIpv4[0]}')

        elif authResultOrigIP:
            #print(f'IPQualityScore: {Fore.LIGHTGREEN_EX}https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}{Fore.RESET}')
            print(f'IPQualityScore: {self.colors.green(f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}")}')
            report.append(f'IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{authResultOrigIP[0]}')

        else:
            #print(f'{Fore.WHITE}Could not detect SMTP Server. Manual reviewing required.{Fore.RESET}')
            print(self.colors.white("Could not detect SMTP Server. Manual reviewing required."))
            report.append(f'Could not detect SMTP Server. Manual reviewing required.')
        
        return ''.join(report)