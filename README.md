
# PMKID WPA2 Cracker

This program is a tool written in Python to recover the pre-shared key of a WPA2 WiFi network without any de-authentication or requiring any clients to be on the network. It targets the weakness of certain access points advertising the PMKID value in EAPOL message 1.

**DISCLAIMER:** This program is STRICTLY for educational and research purposes only. Only use on your own network or with permission.

## Program Usage

```
python pmkidcracker.py -s <ssid> -ap <apmac> -c <clientmac> -p <pmkid> -w <wordlist> -t <threads(optional)>
```
<img width="549" alt="help" src="https://user-images.githubusercontent.com/28621928/233799923-71f70dc1-6750-4b70-a654-54976c696a74.png">

**NOTE:** apmac, clientmac, pmkid must be a hexstring, e.g b8621f50edd9

## How PMKID is Calculated
The two main formulas to obtain a PMKID are as follows: 
1. **Pairwise Master Key (PMK) Calculation:** passphrase + salt(ssid) => PBKDF2(HMAC-SHA1) of 4096 iterations
2. **PMKID Calculation:** HMAC-SHA1[pmk + ("PMK Name" + bssid + clientmac)]

This is just for understanding, both are already implemented in `find_pw_chunk` and `calculate_pmkid`.

## Obtaining the PMKID

Below are the steps to obtain the PMKID manually by inspecting the packets in WireShark. 

**\*You may use Hcxtools or Bettercap to quickly obtain the PMKID without the below steps. The manual way is for understanding.** 

To obtain the PMKID manually from wireshark, put your wireless antenna in monitor mode, start capturing all packets with airodump-ng or similar tools. Then connect to the AP using an invalid password to capture EAPOL 1 message. Follow the next 3 steps to obtain the fields needed for the arguments.

**Open the pcap in WireShark:**

- Filter with `wlan_rsna_eapol.keydes.msgnr == 1` in WireShark to display only EAPOL message 1 packets.
- In EAPOL 1 pkt, Expand IEEE 802.11 QoS Data Field to obtain AP MAC, Client MAC
- In EAPOL 1 pkt, Expand 802.1 Authentication > WPA Key Data > Tag: Vendor Specific > PMKID is at bottom

**If access point is vulnerable, you should see the PMKID value like the below screenshot:**

<img width="469" alt="pmkid" src="https://user-images.githubusercontent.com/28621928/232556774-2ecf784c-4d13-4cd6-9f15-ae8ff095823e.png">

## Demo Run

<img width="431" alt="cracked" src="https://user-images.githubusercontent.com/28621928/232557213-5f5746e7-6cdb-4346-a0c7-31e66c34a7d1.png">

