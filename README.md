# Elyzer

<p align="center">
 <img src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/a649da92-d063-40a2-9dff-6f1fb5996fcb">
</p>

# Table of Contents

- [Elyzer](#elyzer)
  * [Description](#description)
  * [General Informations](#general-informations)
  * [Installation](#installation)
  * [Usage](#usage)
  * [Features](#features)
  * [To-Do](#to-do)
  * [Notes](#notes)
  * [Disclaimer](#disclaimer)

## Description

Elyzer is an e-mail header analyzer capable of detecting potential spoofing attempts. It will give you general information about the e-mail, the route it took, important security headers and the phishing / spoofing results.<br><br>:warning: *This project is under development and changes will be made frequently*.<br>

## General Informations

- Before using this tool, make sure the e-mail header is formated correctly. This tool will parse the header according to RFC 822.
- This tool can ONLY utilize the spoofing / phishing function if the header contains the sender's SMTP Server IPv4 address. IPv6 addresses are currently not supported.
- Microsoft e-mail services are using IPv6 addresses, which on top of that are proxys. Finding the source address is very difficult if not simply impossible.
- PLEASE DO NOT RELY ONLY ON THIS TOOL. Elyzer cannot garantuee you 100% accuracy.

## Installation

**For Unix users:**
```
git clone https://github.com/B0lg0r0v/Elyzer.git
cd Elyzer
pip3 install -r requirements.txt
```

## Usage
Using Elyzer is quite intuitive. Give with the *-f* argument the header file.

**Unix:**
```
python3 elyzer.py -f <FILE>
```

Full Elyzer options:

```
options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Give the E-Mail Header as a file.
  -pa, --passive        Enables the passive mode. DNS resolution is performed passively through VirusTotal &
                        HackerTarget for better OPSEC. You need to add your own VirusTotal API key to use this
                        feature.
  -nd, --no-dns         Enables the no-dns mode. No DNS resolution is performed for best OPSEC. This heavily affects
                        the results !
  -q, --quiet           Quiet mode. Disables banner.
  -j, --json            EXPERIMENTAL FEATURE. Output the results in JSON format.
  -v, --version         show program's version number and exit
  -a ATTACHEMENT, --attachement ATTACHEMENT
                        Check if the file is malicious.
```

Elyzer performs various DNS lookups to compare values for the spoofing function. This could raise OPSEC concerns, especially when dealing with a targeted attack.

If you have OPSEC concerns, you can now use the `-pa` argument to perform DNS lookups passively. This way, you’re no longer *directly* interacting with potential malicious domains, but *indirectly*, making it harder for an adversary to track. However, this CAN impact the results.

```
python3 elyzer.py -f <FILE> -pa
```

If you want the best OPSEC, you can use the `-nd` argument, which enables 'No DNS / Paranoid' mode. This will disable all DNS lookups, allowing you to use Elyzer entirely offline. However, be aware that this will significantly impact the results !

```
python3 elyzer.py -f <FILE> -nd
```

Additionally you can give a file with the `-a` argument to Elyzer. It will then generate you a VirusTotal Link where you can see if the file is potentially malicious or not.

```
python3 elyzer.py -f <MAIL_HEADER_FILE> -a <SUSPICIOUS_FILE>
```

## Features
Here's a quick overview of Elyzer's features:
 - Print general e-mail informations
 - Print relay routing with timestamps
 - Print security headers and check if set correctly
 - Print interesting headers such as "Envelope-From"
 - Print MS-Exchange Headers
 - Spoofing / Phishing analyzer with optional passive DNS lookup

*Spoofing / Phishing detection feature:*
<p align="center">
 <img src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/229052f4-40ec-460e-8789-a0e7947134b5">

## To-Do
- [ ] Add JSON output functionality.
- [ ] Add a functionality to be able to passively query DNS information to reduce OPSEC concerns.


## Notes
Credits for the *getReceivedFields* & the *getFields* functions goes to "spcnvdr" <spcnvdrr@protonmail.com>, Copyright 2020. <br>
Also, thanks to [@triggerfx](https://github.com/triggerfx) for the custom Logo !

## Disclaimer
This tool is primarly created for me as a project to enhance my coding skills and start creating some red team / blue team tools. It is not considered to be the most efficient tool out there.

