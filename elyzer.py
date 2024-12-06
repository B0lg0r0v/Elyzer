from argparse import ArgumentParser
import re
import requests
import json
from core.colors import Colors, banner
from core.utils import Utils
from core.spoofing import Spoofing
from core.exp_json import ExportJson, export_to_json
import os

def checkForUpdates(): 
    try:
        response = requests.get('https://api.github.com/repos/B0lg0r0v/Elyzer/releases/latest')
    except requests.exceptions.ConnectionError:
        #print(f'{Fore.RED}No internet connection.{Fore.RESET}')
        print(Colors.red("No internet connection."))
        exit()    
    
    latestRelease = json.loads(response.text)

    if 'tag_name' in latestRelease:
        latestVersion = latestRelease['tag_name'].lower()

        match = re.search(r'v\d+\.\d\.\d+', latestVersion) #Extract only the version number
        if match:
            latestVersion = match.group(0)

        if CURRENT_VERSION != latestVersion:
            if latestVersion > CURRENT_VERSION:
                print(f'A new version ({latestVersion}) is available. Please download it from the release section on GitHub.\n')
            elif latestVersion == CURRENT_VERSION:
                pass
            elif latestVersion < CURRENT_VERSION:
                pass 

 
if __name__ == '__main__':

    indent = ' ' * 3
    CURRENT_VERSION = 'v0.5.0'
    savings = []

    checkForUpdates()

    parser = ArgumentParser() # Create the Parser.
    parser.add_argument('-f', '--file', help='Give the E-Mail Header as a file.', required=True)
    parser.add_argument('-pa', '--passive', help='Enables the passive mode. DNS resolution is performed passively through VirusTotal & HackerTarget for better OPSEC. You need to add your own VirusTotal API key to use this feature.', action='store_true')
    parser.add_argument('-nd', '--no-dns', help='Enables the no-dns mode. No DNS resolution is performed for best OPSEC. This heavily affects the results !', action='store_true')
    parser.add_argument('-q', '--quiet', help='Quiet mode. Disables banner.', action='store_true')
    parser.add_argument('-j', '--json', help='EXPERIMENTAL FEATURE. Output the results in JSON format.', action='store_true')
    parser.add_argument('-v', '--version', action='version', version=f'Elyzer {CURRENT_VERSION}')
    parser.add_argument('-a', '--attachement', help='Check if the file is malicious.')
    args = parser.parse_args() # Initialize the Parser.

    
    if args.file is not None:  
        utils = Utils(args.file) # Initialize the Utils class.
        spoofing = Spoofing(args.file) # Initialize the Spoofing class.
        expjson = ExportJson(args.file)
        current_dir = os.path.dirname(os.path.abspath(__file__))

        if args.quiet:

            print(Colors.yellow("E-Mail Header Analysis complete"))
            if args.passive:

                if args.json:
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_passive_dns()
                        utils.check_attachment(args.attachement)

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')
                    
                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_passive_dns()

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')
                
                else:
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_passive_dns()
                        utils.check_attachment(args.attachement)
                        
                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_passive_dns()
            
            elif args.no_dns:

                if args.json:
                
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_no_dns()
                        utils.check_attachment(args.attachement)

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')

                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_no_dns()

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')

                else:
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_no_dns()
                        utils.check_attachment(args.attachement)
                    
                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_no_dns()

            else:

                if args.json:
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()
                        utils.check_attachment(args.attachement)

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')

                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')

                else:
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()
                        utils.check_attachment(args.attachement)
                    
                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()

        else:
            banner()
            print(Colors.yellow("E-Mail Header Analysis complete"))
            if args.passive:

                if args.attachement:
                    utils.generalInformation()
                    utils.routing()
                    utils.securityInformations()
                    utils.envelope()
                    spoofing.spoofing_passive_dns()
                    utils.check_attachment(args.attachement)
                
                else:
                    utils.generalInformation()
                    utils.routing()
                    utils.securityInformations()
                    utils.envelope()
                    spoofing.spoofing_passive_dns()
            
            elif args.no_dns:
                
                if args.attachement:
                    utils.generalInformation()
                    utils.routing()
                    utils.securityInformations()
                    utils.envelope()
                    spoofing.spoofing_no_dns()
                    utils.check_attachment(args.attachement)

                else:
                    utils.generalInformation()
                    utils.routing()
                    utils.securityInformations()
                    utils.envelope()
                    spoofing.spoofing_no_dns()

            else:

                if args.json:

                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()
                        utils.check_attachment(args.attachement)

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output)
                        print(f'\nElyzer.json has been saved to {json_file}')
                    
                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()

                        json_output = expjson.jsonoutput()
                        json_file = export_to_json(json_output, os.path.join(current_dir, "elyzer_report.json"))
                        print(f'\nElyzer.json has been saved to {json_file}')

                else:
                    if args.attachement:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()
                        utils.check_attachment(args.attachement)
                    
                    else:
                        utils.generalInformation()
                        utils.routing()
                        utils.securityInformations()
                        utils.envelope()
                        spoofing.spoofing_all_checks()
                
    else:
        parser.error('E-Mail Header is required.')