import re
import os
import json
from core.utils import Utils
from datetime import datetime
from core.spoofing import Spoofing

def parse_key_value(text):
        result = {}
        for line in text.split('\n'):
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                result[key.strip()] = value.strip()
        return result

def export_to_json(results, filename=None):
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"email_analysis_{timestamp}.json"
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        
        return filename

class ExportJson:

    def __init__(self, file):
        self.utils = Utils(file)
        self.spoofing = Spoofing(file)


    def jsonoutput(self):
        return {
            "general_information": self.parse_general_information(),
            "security_information": self.parse_security_information(),
            "routing": self.parse_routing(),
            "envelope": self.parse_envelope(),
            "spoofing_check": self.parse_spoofing_check(),
        }


    def parse_general_information(self):
        return parse_key_value(self.utils.generalInformation())

    def parse_security_information(self):

        security_info = parse_key_value(self.utils.securityInformations())
        
        # Parse DKIM signature
        if 'DKIM Signature' in security_info:
            dkim = {}
            for part in security_info['DKIM Signature'].split(';'):
                if '=' in part:
                    key, value = part.split('=', 1)
                    dkim[key.strip()] = value.strip()
            security_info['DKIM Signature'] = dkim

        return security_info

    def parse_routing(self):
        routing_info = self.utils.routing().split('\n\n')
        hops = []
        for hop in re.findall(r'Hop \d+ \|↓\|: (.*)', routing_info[0]):
            hop_parts = hop.split(' TO ')
            from_part = hop_parts[0].split('FROM ')[1]
            to_part, with_part = hop_parts[1].split(' WITH ')
            hops.append({
                'from': from_part,
                'to': to_part,
                'with': with_part
            })
        
        timestamps = []
        for timestamp in re.findall(r'Hop \d+: (.*)', routing_info[1]):
            ts_parts = timestamp.split(', Delta: ')
            timestamps.append({
                'timestamp': ts_parts[0],
                'delta': ts_parts[1] if len(ts_parts) > 1 else None
            })

        return {
            'hops': [dict(hop, **ts) for hop, ts in zip(hops, timestamps)]
        }

    def parse_envelope(self):
        envelope_info = parse_key_value(self.utils.envelope())
        
        # Parse MS Exchange Organization Headers
        if 'MS Exchange Organization Headers' in envelope_info:
            ms_headers = parse_key_value(envelope_info['MS Exchange Organization Headers'])
            envelope_info['MS Exchange Organization'] = ms_headers
            del envelope_info['MS Exchange Organization Headers']

        return envelope_info
    

    def parse_spoofing_check(self):
        spoofing_info = self.spoofing.spoofing_all_checks().split('\n\n')
        result = {
            'smtp_server_mismatch': {},
            'field_mismatches': {},
            'external_checks': {}
        }

        for section in spoofing_info:
            if section.startswith('Checking for SMTP Server Mismatch'):
                result['smtp_server_mismatch'] = {'details': section.split('...\n')[1].strip()}
            elif section.startswith('Checking for Field Mismatches'):
                for line in section.split('\n')[1:]:
                    if '→' in line:
                        key, value = line.split('→')
                        result['field_mismatches'][key.strip()] = value.strip()
            elif section.startswith('Checking with VirusTotal'):
                result['external_checks']['virustotal'] = parse_key_value(section)
            elif section.startswith('Checking with AbuseIPDB'):
                result['external_checks']['abuseipdb'] = parse_key_value(section)
            elif section.startswith('Checking with IPQualityScore'):
                result['external_checks']['ipqualityscore'] = parse_key_value(section)

        return result
    
    def parse_spoofing_no_dns(self):
        spoofing_info = self.spoofing.spoofing_no_dns().split('\n\n')
        result = {
            'smtp_server_mismatch': {},
            'field_mismatches': {},
            'external_checks': {}
        }

        for section in spoofing_info:
            if section.startswith('Checking for SMTP Server Mismatch'):
                result['smtp_server_mismatch'] = {'details': section.split('...\n')[1].strip()}
            elif section.startswith('Checking for Field Mismatches'):
                for line in section.split('\n')[1:]:
                    if '→' in line:
                        key, value = line.split('→')
                        result['field_mismatches'][key.strip()] = value.strip()
            elif section.startswith('Checking with VirusTotal'):
                result['external_checks']['virustotal'] = parse_key_value(section)
            elif section.startswith('Checking with AbuseIPDB'):
                result['external_checks']['abuseipdb'] = parse_key_value(section)
            elif section.startswith('Checking with IPQualityScore'):
                result['external_checks']['ipqualityscore'] = parse_key_value(section)

        return result
