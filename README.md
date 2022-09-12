# Sandman

![Image](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white") ![image](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) ![image](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

Sandman is a backdoor that meant to work on hardened networks during red team engagements.

Sandman works as a stager and leverages NTP (protocol to sync time & date) to get and run an arbitrary **shellcode** from a pre defined server.

Since NTP is a protocol that is overlooked by many defenders resulting wide network accessability.

## Usage

![sandman](images/sandman.png)

### SandmanServer (Usage)

Run on windows / *nix machine:

```sh
python3 sandman_server.py "Network Adapter" "Payload Url" "optional: ip to spoof"
```

- Network Adapter: The adapter that you want the server to listen on (for example: Ethernet for Windows, eth0 for *nix).

- Payload Url: The URL to your shellcode, it could be your agent (for example, CobaltStrike or meterpreter) or another stager.

- IP to Spoof: If you want to spoof a legitiment IP address (for example, time.microsoft.com's ip address).

### SandmanBackdoor (Usage)

To start, you can compile the SandmanBackdoor as [mentioned below](#setup), because it is a single lightweight C# executable you can execute it via ExecuteAssembly, run it as a NTP provider or just execute / inject it.

**NOTE: Make sure you are compiling with the x64 option and not the any cpu option!**

## Capabilities

- Getting and executing an arbitrary payload from an attacker's controlled server.

- Can work on hardened networks since NTP is usually allowed in FW.

- Impsersonating a legitiment NTP server via IP spoofing.

## Setup

### SandmanServer (Setup)

- Python 3.9
- Requiremenets specified in the [requirements](/SandmanServer/requirements.txt) file.

### SandmanBackdoor (Setup)

To compile the backdoor itself I used Visual Studio 2022, but as mentioned in the [usage section](#usage) it can be compiled with both VS2022 and csc.

## IOCs

- A shellcode is injected to RuntimeBroker.

- Suspicious NTP communication, starts with known magic header.

- YARA rule.

## Contributes

- [Orca](https://github.com/ORCx41/)

- Special thanks to [Tim McGuffin](https://twitter.com/NotMedic) for the time [provider idea](https://twitter.com/NotMedic/status/1561354598744473601).

Thanks to who already contributed and I'll happily accept contribution, make a pull request and I will review it!
