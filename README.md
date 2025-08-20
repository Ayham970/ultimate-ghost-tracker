# Ultimate Ghost Tracker

**Ultimate Ghost Tracker** is a professional OSINT (Open Source Intelligence) investigation platform written in Python. It provides advanced intelligence gathering and analysis modules for cybersecurity professionals, investigators, and enthusiasts.

## Features

- **IP Intelligence:** Analyze IP addresses for geolocation, reverse DNS, reputation, and risk scoring.
- **Phone Intelligence:** Investigate phone numbers using carrier, geolocation, and time zone information.
- **Username Investigation:** Search for usernames across social platforms and services.
- **Email/Domain Intelligence:** Analyze email addresses and domains for validity, reputation, and suspiciousness.
- **Cryptocurrency Investigation:** Validate and analyze crypto addresses (Bitcoin, Ethereum, Litecoin, etc.).
- **Threat Intelligence:** Assess potential risks and threats associated with IP addresses.
- **Investigation Tracking:** Track, save, and export investigation results.
- **System Status & History:** View system status and investigation history.
- **Comprehensive Reporting:** Export investigation reports for further analysis.

## Getting Started

### Prerequisites

- Python 3.8+
- `pip install requests phonenumbers`

### Installation

```bash
git clone https://github.com/Ayham970/ultimate-ghost-tracker.git
cd ultimate-ghost-tracker
```

### Usage

Run the main application:

```bash
python3 ultimate-ghost-tracker.py
```

You will be presented with a menu to select different intelligence modules. Follow the prompts to input targets (IP address, phone number, username, email, domain, or crypto address) and receive intelligence reports.


## Modules Overview

- **IP Intelligence:** Geolocation, ISP, reputation, risk scoring, Google Maps links.
- **Phone Intelligence:** Carrier, geolocation, time zone.
- **Username Investigation:** OSINT on usernames.
- **Email/Domain Intelligence:** Validity checks, reputation, suspicious domain detection.
- **Cryptocurrency Investigation:** Address format and currency detection.
- **Threat Intelligence:** Malicious activity assessment.
- **Export/History:** Save and review investigation results.

## Example

```
$ python ultimate-ghost-tracker.py
🚀 Initializing Ultimate Ghost Tracker...
🎯 Select module (0-9, ? for help): 1
🌐 ADVANCED IP INTELLIGENCE INVESTIGATION
Enter target IP address: 8.8.8.8
...
📋 IP INTELLIGENCE REPORT
Country: United States
Reputation Score: 85/100
Risk Score: 10/100
...
```

## Author

Developed by [Ayham970](https://github.com/Ayham970)

---

*For help, use '?' in the main menu. Happy investigating!*
