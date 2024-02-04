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
  * [Notes](#notes)
  * [Disclaimer](#disclaimer)

## Description

Elyzer is an e-mail header analyzer capable of detecting potential spoofing attempts. It will give you general information about the e-mail, the route it took, important security headers and the phishing / spoofing results. 

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
**For Windows users:**<br><br>
Get the compiled version from the release section. The usage is the same as for unix users.

## Usage
Using Elyzer is quite intuitive. Give with the *-f* argument the header file.

**Unix:**
```
python3 elyzer.py -f <FILE>
```
**Windows**
```
.\Elyzer.exe -f <FILE>
```

## Features
Here's a quick overview of Elyzer's features:
 - Print general e-mail informations
 - Print relay routing with timestamps
 - Print security headers and check if set correctly
 - Print interesting headers such as "Envelope-From"
 - Print MS-Exchange Headers
 - Spoofing / Phishing analyzer

*Spoofing / Phishing detection feature:*
<p align="center">
 <img src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/229052f4-40ec-460e-8789-a0e7947134b5">

## Notes
Credits for the *getReceivedFields* & the *getFields* functions goes to "spcnvdr" <spcnvdrr@protonmail.com>, Copyright 2020.

## Disclaimer
This tool is primarly created for me as a project to enhance my coding skills and start creating some red team / blue team tools. It is not considered to be the most efficient tool out there.

