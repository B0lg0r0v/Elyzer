from core.colors import Colors
from email.parser import BytesParser
from email.header import decode_header
import dns.resolver
import re
from datetime import datetime
import sys
import hashlib


class Utils:
    def __init__(self, header):
        self.eHeader = header
        self.colors = Colors()

    def getFields(self):
        fields = []
        # First find all the fields present in the email headers
        with open(self.eHeader, "rb") as fp:
            headers = BytesParser().parse(fp)

        # Add each field to a list
        for j in headers:
            fields.append(j + ":")

        return fields

    
    def getReceivedFields(self):
        # credits goes to spcnvdr for helping me with this part of the code. https://github.com/spcnvdr/tracemail/tree/master Copyright 2020 spcnvdr <spcnvdrr@protonmail.com>

        #------------------------get all the "Receveid: from" Fields------------------------# 

        found = False
        tmp = ''
        receivedFields =[]
        finalReceivedFields = []
        fields = self.getFields()

        with open(self.eHeader, 'r', encoding='UTF-8') as header:
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
        
    def resolveIP(self, domain):
        try:
            resolve4 = dns.resolver.resolve(domain, 'A')
            #resolve6 = dns.resolver.resolve(domain, 'AAAA')
            if resolve4:
                for resolved4 in resolve4:
                    return f'{resolved4}'
        except:
            return f'{self.colors.red("Error.")}'
        

    def routing(self):
        
        routing =[]
        counter= 0 # counter for the hops

        print(f'\n{self.colors.light_blue("Relay Routing: ")}')
        routing.append(f'Relay Routing:\n')

        for y in reversed(self.getReceivedFields()):
            
            # Regex for the field values
            receivedMatch = re.findall(r'received: from ([\w\-.:]+)', y, re.IGNORECASE)
            byMatch = re.findall(r'by ([\w\-.:]+)', y, re.IGNORECASE)
            withMatch = re.findall(r'with ([\w\-.:]+)', y, re.IGNORECASE)

            counter += 1 
            try:
                if len(receivedMatch) != 0:
                    print(f'Hop {counter} |↓|: FROM {self.colors.green(receivedMatch[0].lower())} TO {self.colors.green(byMatch[0].lower())} WITH {self.colors.cyan(withMatch[0].lower())}')
                    routing.append(f'Hop {counter} |↓|: FROM {receivedMatch[0].lower()} TO {byMatch[0].lower()} WITH {withMatch[0].lower()}\n')
                else:
                    print(f'{self.colors.yellow("No match found for Hop " + str(counter))}')
            except Exception as e:
                print(f'{self.colors.red("Error: " + str(e) + ". Skipping...")}')
        
        print(f'\n{self.colors.light_blue("Timestamps between Hops: ")}')
        routing.append(f'\nTimestamps between Hops:\n')

        dateCounter = 1 #separate counter for the hops in the timestamps
        prevTimestamp = None
        delta = None

        for x in reversed(self.getReceivedFields()):
            # There are potentialy 3 different date formats in the received fields.
            # That's why we have to check for each one of them.
            dateMatch1 = re.findall(r'\S{3},[ ]{0,4} \d{1,2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2} [+-]\d{4}', x ,re.IGNORECASE)
            dateMatch2 = re.findall(r'\S{3}, \d{2} \S{3} \d{1,4} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)
            dateMatch3 = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{0,10} [+-]\d{4}', x, re.IGNORECASE)

            if dateMatch1 is not None:
                for date in reversed(dateMatch1):
                    currentTimeStamp = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z')
                    if prevTimestamp:
                        delta = currentTimeStamp - prevTimestamp
                        print(f'Hop {dateCounter}: {self.colors.green(date)}, {self.colors.cyan("Delta: " + str(delta))}')
                    routing.append(f'Hop {dateCounter}: {date}, Delta: {delta if delta is not None else "N/A"}\n')
                    dateCounter += 1
                    prevTimestamp = currentTimeStamp
            
            elif dateMatch2 is not None:
                for date in reversed(dateMatch2):
                    currentTimeStamp = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S.%f %z')
                    if prevTimestamp:
                        delta = currentTimeStamp - prevTimestamp
                        print(f'Hop {dateCounter}: {self.colors.green(date)}, {self.colors.cyan("Delta: " + str(delta))}')
                    routing.append(f'Hop {dateCounter}: {date}, Delta: {delta if delta is not None else "N/A"}\n')
                    dateCounter += 1
                    prevTimestamp = currentTimeStamp

            elif dateMatch3 is not None:
                for date in reversed(dateMatch3):
                    currentTimeStamp = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f %z')
                    if prevTimestamp:
                        delta = currentTimeStamp - prevTimestamp
                        print(f'Hop {dateCounter}: {self.colors.green(date)}, {self.colors.cyan("Delta: " + str(delta))}')
                    routing.append(f'Hop {dateCounter}: {date}\n, Delta: {delta if delta is not None else "N/A"}\n')
                    dateCounter += 1
                    prevTimestamp = currentTimeStamp

        return ''.join(routing)


    def generalInformation(self):
        try:
            with open(self.eHeader, 'r', encoding='UTF-8') as header:
                raw_content = header.read()
                content = BytesParser().parsebytes(raw_content.encode('UTF-8'))
        except FileNotFoundError:
            print(f'{self.colors.red("File not found.")}')
            sys.exit(1)
        except Exception as e:
            print(f'{self.colors.red(f"Error reading file: {e}")}')
            sys.exit(1)

        # Trying to decode the subject
        subject = content.get('subject', 'No subject found')
        if subject != 'No subject found':
            decoded_subject = decode_header(subject)
            decodedHeader = ''
            for part, charset in decoded_subject:
                try:
                    decodedHeader += part.decode(charset or 'utf8') if isinstance(part, bytes) else part
                except UnicodeDecodeError:
                    decodedHeader += part.decode('iso-8859-1') if isinstance(part, bytes) else part
        else:
            decodedHeader = subject

        print(f'\n{self.colors.light_blue("General Information:")}')

        from_field = content.get("from", "No 'From' field found")
        to_field = content.get("to", "No 'To' field found")
        date_field = content.get("date", "No 'Date' field found")

        print(f'From: {self.colors.green(from_field)}')
        print(f'To: {self.colors.green(to_field)}')
        print(f'Subject: {self.colors.green(decodedHeader)}')
        print(f'Date: {self.colors.green(date_field)}')

        return f'From: {from_field}\nTo: {to_field}\nSubject: {decodedHeader}\nDate: {date_field}'


    def securityInformations(self):
        try:
            with open(self.eHeader, 'r', encoding='UTF-8') as header:
                content = BytesParser().parsebytes(header.read().encode('UTF-8'))
        except FileNotFoundError:
            self.colors.red("File not found.")
            sys.exit(1)

        secInfos = []

        print(f'\n{self.colors.light_blue("Security Informations: ")}')
        secInfos.append(f'\nSecurity Informations:\n')

        if content['received-spf'] is not None:
            if 'fail' in content['received-spf'].lower():
                print(f'Received SPF: {self.colors.red(content["received-spf"])}')
                secInfos.append(f'Received SPF: {content["received-spf"]}')
            
            elif 'None' in content['received-spf']:
                print(f'Received SPF: {self.colors.red(content["received-spf"])}')
                secInfos.append(f'Received SPF: {content["received-spf"]}')

            else:
                print(f'Received SPF: {self.colors.green(content["received-spf"])}')
                secInfos.append(f'Received SPF: {content["received-spf"]}')
        else:
            print(f'Received SPF: {self.colors.red("No Received SPF")}')
            secInfos.append(f'Received SPF: No Received SPF') 


        if content['dkim-signature'] is not None:
            print(f'DKIM Signature: {self.colors.green(content["dkim-signature"])}')
            secInfos.append(f'DKIM Signature: {content["dkim-signature"]}')
        else:
            print(f'DKIM Signature: {self.colors.red("No DKIM Signature")}')
            secInfos.append(f'DKIM Signature: No DKIM Signature')
        

        if content['dmarc'] is not None:
            print(f'DMARC: {self.colors.green(content["dmarc"])}')
            secInfos.append(f'DMARC: {content["dmarc"]}')
        else:
            print(f'DMARC: {self.colors.red("No DMARC")}')
            secInfos.append(f'DMARC: No DMARC')
        

        if content['authentication-results'] is not None:
            
            if 'spf=fail' in content['authentication-results'].lower():
                print(f'Authentication Results: {self.colors.red(content["authentication-results"])}')
                secInfos.append(f'Authentication Results: {content["authentication-results"]}')
            else:
                print(f'Authentication Results: {self.colors.green(content["authentication-results"])}')
                secInfos.append(f'Authentication Results: {content["authentication-results"]}')
                
        else:
            print(f'Authentication Results: {self.colors.red("No Authentication Results")}')
            secInfos.append(f'Authentication Results: No Authentication Results')

        
        if content['x-forefront-antispam-report'] is not None:
            print(f'X-Forefront-Antispam-Report: {self.colors.green(content["x-forefront-antispam-report"])}')
            secInfos.append(f'X-Forefront-Antispam-Report: {content["x-forefront-antispam-report"]}')
        else:
            print(f'X-Forefront-Antispam-Report: {self.colors.red("No X-Forefront-Antispam-Report")}')
            secInfos.append(f'X-Forefront-Antispam-Report: No X-Forefront-Antispam-Report')


        if content['x-microsoft-antispam'] is not None:
            print(f'X-Microsoft-Antispam: {self.colors.green(content["x-microsoft-antispam"])}')
            secInfos.append(f'X-Microsoft-Antispam: {content["x-microsoft-antispam"]}')
        else:
            print(f'X-Microsoft-Antispam: {self.colors.red("No X-Microsoft-Antispam")}')
            secInfos.append(f'X-Microsoft-Antispam: No X-Microsoft-Antispam')

        return '\n'.join(secInfos)

    def envelope(self):
        try:
            with open(self.eHeader, 'r', encoding='UTF-8') as header:
                content = BytesParser().parsebytes(header.read().encode('UTF-8'))
        except FileNotFoundError:
            self.colors.red("File not found.")
            sys.exit(1)

        eenvelope = []

        print(f'\n{self.colors.light_blue("Other Interesting Headers: ")}')
        eenvelope.append(f'\nOther Interesting Headers:\n')


        if content['X-ORIG-EnvelopeFrom'] is not None:
            fromMatch = re.search(r'<(.*)>', content['from'])

            if content['X-ORIG-EnvelopeFrom'] == 'anonymous@':
                print(f'Envelope From: {self.colors.red(content["X-ORIG-EnvelopeFrom"])}')
                eenvelope.append(f'Envelope From: {content["X-ORIG-EnvelopeFrom"]}')
            
            elif content['X-ORIG-EnvelopeFrom'] != fromMatch.group(1):
                print(f'Envelope From: {self.colors.red(f"POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content['from']}) NOT EQUAL ({content['X-ORIG-EnvelopeFrom']})")}')
                eenvelope.append(f'POTENTIAL SPOOFING ATTACK DETECTED: FROM ({content["from"]}) NOT EQUAL ({content["X-ORIG-EnvelopeFrom"]})')

            else:
                print(f'Envelope From: {self.colors.green(content["X-ORIG-EnvelopeFrom"])}')
                eenvelope.append(f'Envelope From: {content["X-ORIG-EnvelopeFrom"]}')
        else:
            print(f'Envelope From: {self.colors.red("No Envelope From")}')
            eenvelope.append(f'Envelope From: No Envelope From')


        if content['return-path'] is not None:
            print(f'Return Path: {self.colors.green(content["return-path"])}')
            eenvelope.append(f'Return Path: {content["return-path"]}')
        else:
            print(f'Return Path: {self.colors.red("No Return Path")}')
            eenvelope.append(f'Return Path: No Return Path')

        if content['message-id'] is not None:
            print(f'Message ID: {self.colors.green(content["message-id"])}')
            eenvelope.append(f'Message ID: {content["message-id"]}')
        else:
            print(f'Message ID: {self.colors.red("No Message ID")}')
            eenvelope.append(f'Message ID: No Message ID')

        if content['mime-version'] is not None:
            print(f'MIME-Version: {self.colors.green(content["mime-version"])}')
            eenvelope.append(f'MIME-Version: {content["mime-version"]}')
        else:
            print(f'MIME-Version: {self.colors.red("No MIME-Version")}')
            eenvelope.append(f'MIME-Version: No MIME-Version')

        if content['authentication-results-original'] is not None:
            if 'spf=fail' in content['authentication-results-original'].lower():
                print(f'Authentication-Results-Original: {self.colors.red(content["authentication-results-original"])}')
                eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
            
            elif 'spf=pass' in content['authentication-results-original'].lower():
                print(f'Authentication-Results-Original: {self.colors.green(content["authentication-results-original"])}')
                eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
            
            else:
                print(f'Authentication-Results-Original: {self.colors.yellow(content["authentication-results-original"])}')
                eenvelope.append(f'Authentication-Results-Original: {content["authentication-results-original"]}')
        else:
            print(f'Authentication-Results-Original: {self.colors.red("No Authentication-Results-Original")}')
            eenvelope.append(f'Authentication-Results-Original: No Authentication-Results-Original')

        print(f'{self.colors.cyan("\n<---------MS Exchange Organization Headers--------->\n")}')
        eenvelope.append(f'\n<---------MS Exchange Organization Headers--------->\n')

        if content['x-ms-exchange-organization-authas'] is not None:
            if 'anonymous' or 'Anonymous' in content['x-ms-exchange-organization-authas']:
                print(f'X-MS-Exchange-Organization-AuthAs: {self.colors.yellow(content["x-ms-exchange-organization-authas"])}')
                eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: {content["x-ms-exchange-organization-authas"]}')
            else:
                print(f'X-MS-Exchange-Organization-AuthAs: {self.colors.green(content["x-ms-exchange-organization-authas"])}')
                eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: {content["x-ms-exchange-organization-authas"]}')
        else:
            print(f'X-MS-Exchange-Organization-AuthAs: {self.colors.red("No X-MS-Exchange-Organization-AuthAs")}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthAs: No X-MS-Exchange-Organization-AuthAs')

        if content['x-ms-exchange-organization-authsource'] is not None:
            print(f'X-MS-Exchange-Organization-AuthSource: {self.colors.green(content["x-ms-exchange-organization-authsource"])}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthSource: {content["x-ms-exchange-organization-authsource"]}')
        else:
            print(f'X-MS-Exchange-Organization-AuthSource: {self.colors.red("No X-MS-Exchange-Organization-AuthSource")}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthSource: No X-MS-Exchange-Organization-AuthSource')

        if content['x-ms-exchange-organization-authmechanism'] is not None:
            print(f'X-MS-Exchange-Organization-AuthMechanism: {self.colors.green(content["x-ms-exchange-organization-authmechanism"])}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthMechanism: {content["x-ms-exchange-organization-authmechanism"]}')
        else:
            print(f'X-MS-Exchange-Organization-AuthMechanism: {self.colors.red("No X-MS-Exchange-Organization-AuthMechanism")}')
            eenvelope.append(f'X-MS-Exchange-Organization-AuthMechanism: No X-MS-Exchange-Organization-AuthMechanism')

        if content['x-ms-exchange-organization-network-message-id'] is not None:
            print(f'X-MS-Exchange-Organization-Network-Message-Id: {self.colors.green(content["x-ms-exchange-organization-network-message-id"])}')
            eenvelope.append(f'X-MS-Exchange-Organization-Network-Message-Id: {content["x-ms-exchange-organization-network-message-id"]}')
        else:
            #print(f'X-MS-Exchange-Organization-Network-Message-Id: {Fore.LIGHTRED_EX}No X-MS-Exchange-Organization-Network-Message-Id{Fore.RESET}')
            print(f'X-MS-Exchange-Organization-Network-Message-Id: {self.colors.red("No X-MS-Exchange-Organization-Network-Message-Id")}')
            eenvelope.append(f'X-MS-Exchange-Organization-Network-Message-Id: No X-MS-Exchange-Organization-Network-Message-Id')
        
        print(f'{self.colors.cyan("\n<-------------------------------------------------->")}')
        eenvelope.append(f'\n<-------------------------------------------------->\n')

        return '\n'.join(eenvelope)
    
    def check_attachment(self, attachment):
        result = []
        indent = "    "

        #print(f'\n\n{Fore.LIGHTBLUE_EX}Checking the attachment...{Fore.RESET}')
        print(Colors.light_blue("\nChecking the attachment..."))
        result.append('\n\nChecking the attachment...\n')
        
        sha256 = hashlib.sha256()
        BUFFER = 65536
        
        with open(attachment, 'rb') as file:
            while True:
                data = file.read(BUFFER)
                if not data:
                    break
                
                sha256.update(data)

        #print(f'{indent}--> Link: {Fore.LIGHTGREEN_EX}https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection{Fore.RESET}')
        print(f'{indent}--> Link: {Colors.green(f"https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection")}')
        result.append(f'--> Link: https://www.virustotal.com/gui/file/{sha256.hexdigest()}/detection')

        return '\n'.join(result)
    

