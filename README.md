# Elyzer

<p align="center">
<img width="450" alt="Capture d’écran 2023-12-04 à 14 32 41" src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/b9c11fe1-72cd-4364-9dc8-c1adc0cc748d">
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

Elyzer is an e-mail header analyzer tool capable of detecting potential spoofing attempts. It will give you general information about the e-mail, the route it took, important security headers and the phishing / spoofing results. 

<p align="center">
 <img width="750" alt="Capture d’écran 2023-12-04 à 14 32 41" src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/70939c64-646e-4089-ad1e-3b3f78254127">
</p>

## General Informations

- Before using this tool, make sure the e-mail header is formated correctly. This tool will parse the header according to RFC 822.
- This tool can ONLY utilize the spoofing / phsing function if the header contains the sender's SMTP Server IPv4 address. IPv6 addresses are currently not supported.
- Microsoft e-mail services are using IPv6 addresses, which on top of that are proxys. Finding the source address is very difficult if not simply impossible. 

## Installation

```
git clone https://github.com/B0lg0r0v/Elyzer.git
cd Elyzer
pip3 install -r requirements.txt
```

## Usage
Using Elyzer is quite intuitive. Give with the *-f* argument the header file.

<img width="600" alt="grafik" src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/8f6eb75c-934d-4aee-b508-c41021bd33db">

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
 <img width="1000" alt="grafik" src="https://github.com/B0lg0r0v/Elyzer/assets/115954804/d275fa27-7b63-4797-ad62-7e6e0386e666">
</p>

## Notes
Credits for the *getReceivedFields* & the *getFields* functions goes to "spcnvdr" <spcnvdrr@protonmail.com>, Copyright 2020.

## Disclaimer
This tool is primarly created for me as a project to enhance my coding skills and start creating some red team / blue team tools. It is not considered to be the most efficient tool out there.

