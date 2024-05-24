import argparse
import re
import time
import sys
import os
import random
import string
import importlib
import hashlib
from copy import deepcopy
from time import sleep
from datetime import datetime
from lib.Payload import Payload, Chunked, EndChunk
from lib.EasySSL import EasySSL
from lib.colorama import Fore, Style
from urllib.parse import urlparse

class Desyncr:
    def __init__(self, configfile, smhost, smport=443, url="", method="POST", endpoint="/", SSLFlag=False, logh=None, smargs=None):
        self._configfile = configfile
        self._host = smhost
        self._port = smport
        self._method = method
        self._endpoint = endpoint
        self._vhost = smargs.vhost
        self._url = url
        self._timeout = float(smargs.timeout)
        self.ssl_flag = SSLFlag
        self._logh = logh
        self._quiet = smargs.quiet
        self._exit_early = smargs.exit_early
        self._attempts = 0
        self._cookies = []

    def _test(self, payload_obj):
        try:
            web = EasySSL(self.ssl_flag)
            web.connect(self._host, self._port, self._timeout)
            web.send(str(payload_obj).encode())
            start_time = datetime.now()
            res = web.recv_nb(self._timeout)
            end_time = datetime.now()
            web.close()
            if res is None:
                delta_time = end_time - start_time
                if delta_time.seconds < (self._timeout - 1):
                    return (2, res, payload_obj)  # Return code 2 if disconnected before timeout
                return (1, res, payload_obj)  # Return code 1 if connection timed out

            # Filter out problematic characters
            res_filtered = "".join(chr(single) if single <= 0x7F else '\x30' for single in res)
            res = res_filtered
            return (0, res, payload_obj)  # Return code 0 if normal response returned

        except Exception as exception_data:
            return (-1, None, payload_obj)  # Return code -1 if some exception occurred

    def _get_cookies(self):
        RN = "\r\n"
        try:
            cookies = []
            web = EasySSL(self.ssl_flag)
            web.connect(self._host, self._port, 2.0)
            p = Payload()
            p.host = self._host
            p.method = "GET"
            p.endpoint = self._endpoint
            p.header = f"GET {self._endpoint}?cb={random.random()} HTTP/1.1{RN}"
            p.header += f"Host: {self._host}{RN}"
            p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
            p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
            p.header += "Content-Length: 0" + RN
            p.body = ""
            web.send(str(p).encode())
            sleep(0.5)
            res = web.recv_nb(2.0)
            web.close()

            if res is not None:
                res = res.decode().split(RN)
                for elem in res:
                    if len(elem) > 11 and elem.lower().startswith("set-cookie:"):
                        cookie = elem[11:].split(";")[0] + ';'
                        cookies.append(cookie)
                print_info(f"Cookies : {Fore.CYAN}{len(cookies)}{Fore.MAGENTA} (Appending to the attack)", self._logh)
                self._cookies.extend(cookies)
                return True

        except Exception as exception_data:
            print_info(f"Error : {Fore.CYAN}Unable to connect to host{Fore.MAGENTA}", self._logh)
        return False

    def run(self):
        RN = "\r\n"
        mutations = {}
        if not self._get_cookies():
            return

        if not os.path.isabs(self._configfile):
            self._configfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "configs", self._configfile)
        try:
            with open(self._configfile) as f:
                script = f.read()
        except:
            print_info(f"Error : {Fore.CYAN}Cannot find config file{Fore.MAGENTA}", self._logh)
            exit(1)
        
        exec(script)
        for mutation_name in mutations.keys():
            if self._create_exec_test(mutation_name, mutations[mutation_name]) and self._exit_early:
                break
            if self._quiet:
                sys.stdout.write("\r" + " " * 100 + "\r")

    def _check_tecl(self, payload, ptype=0):
        te_payload = deepcopy(payload)
        te_payload.host = self._vhost if self._vhost else self._host
        te_payload.method = self._method
        te_payload.endpoint = self._endpoint
        if self._cookies:
            te_payload.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
        te_payload.cl = 6 if not ptype else 5
        te_payload.body = EndChunk + "X"
        return self._test(te_payload)

    def _check_clte(self, payload, ptype=0):
        te_payload = deepcopy(payload)
        te_payload.host = self._vhost if self._vhost else self._host
        te_payload.method = self._method
        te_payload.endpoint = self._endpoint
        if self._cookies:
            te_payload.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
        te_payload.cl = 4 if not ptype else 11
        te_payload.body = Chunked("Z") + EndChunk
        return self._test(te_payload)

    def _create_exec_test(self, name, te_payload):
        def pretty_print(name, dismsg):
            spacing = 13
            sys.stdout.write("\r" + " " * 100 + "\r")
            msg = f"{Style.BRIGHT}{Fore.MAGENTA}[{Fore.CYAN}{name}{Fore.MAGENTA}]{' ' * (spacing - len(name))}: {dismsg}"
            sys.stdout.write(CF(msg + Style.RESET_ALL))
            sys.stdout.flush()
            if dismsg[-1] == "\n":
                plaintext = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', msg)
                if self._logh:
                    self._logh.write(plaintext)
                    self._logh.flush()

        def write_payload(smhost, payload, ptype):
            furl = f"https_{smhost.replace('.', '_')}" if self.ssl_flag else f"http_{smhost.replace('.', '_')}"
            _me = os.readlink(sys.argv[0]) if os.path.islink(sys.argv[0]) else sys.argv[0]
            fname = os.path.realpath(os.path.dirname(_me)) + f"/payloads/{furl}_{ptype}_{name}.txt"
            pretty_print("CRITICAL", f"{Fore.MAGENTA}{ptype} Payload: {Fore.CYAN}{fname}{Fore.MAGENTA} URL: {Fore.CYAN}{self._url}\n")
            with open(fname, 'wb') as file:
                file.write(bytes(str(payload), 'utf-8'))

        pretty_print(name, "Checking TECL...")
        start_time = time.time()
        tecl_res = self._check_tecl(te_payload, 0)
        tecl_time = time.time() - start_time

        pretty_print(name, "Checking CLTE...")
        start_time = time.time()
        clte_res = self._check_clte(te_payload, 0)
        clte_time = time.time() - start_time

        if clte_res[0] == 1:
            clte_res2 = self._check_clte(te_payload, 1)
            if clte_res2[0] == 0:
                self._attempts += 1
                if self._attempts < 3:
                    return self._create_exec_test(name, te_payload)
                else:
                    dismsg = f"{Fore.RED}Potential CLTE Issue Found{Fore.MAGENTA} - {Fore.CYAN}{self._method}{Fore.MAGENTA} @ {Fore.CYAN}{['http://', 'https://'][self.ssl_flag]}{self._host}{self._endpoint}{Fore.MAGENTA} - {Fore.CYAN}{self._configfile.split('/')[-1]}\n"
                    pretty_print(name, dismsg)
                    write_payload(self._host, clte_res[2], "CLTE")
                    self._attempts = 0
                    return True
            else:
                dismsg = f"{Fore.YELLOW}CLTE TIMEOUT ON BOTH LENGTH 4 AND 11{['\n', ''][self._quiet]}"
                pretty_print(name, dismsg)

        elif tecl_res[0] == 1:
            tecl_res2 = self._check_tecl(te_payload, 1)
            if tecl_res2[0] == 0:
                self._attempts += 1
                if self._attempts < 3:
                    return self._create_exec_test(name, te_payload)
                else:
                    dismsg = f"{Fore.RED}Potential TECL Issue Found{Fore.MAGENTA} - {Fore.CYAN}{self._method}{Fore.MAGENTA} @ {Fore.CYAN}{['http://', 'https://'][self.ssl_flag]}{self._host}{self._endpoint}{Fore.MAGENTA} - {Fore.CYAN}{self._configfile.split('/')[-1]}\n"
                    pretty_print(name, dismsg)
                    write_payload(self._host, tecl_res[2], "TECL")
                    self._attempts = 0
                    return True
            else:
                dismsg = f"{Fore.YELLOW}TECL TIMEOUT ON BOTH LENGTH 5 AND 6{['\n', ''][self._quiet]}"
                pretty_print(name, dismsg)

        else:
            if self._quiet:
                sys.stdout.write("\r" + " " * 100 + "\r")
            dismsg = f"{Fore.GREEN}None{['\n', ''][self._quiet]}"
            pretty_print(name, dismsg)
        return False

def print_info(msg, logh=None):
    spacing = 10
    sys.stdout.write("\r" + " " * 100 + "\r")
    msg = f"{Style.BRIGHT}{Fore.MAGENTA}[{Fore.CYAN}INFO{Fore.MAGENTA}]{' ' * (spacing - len('INFO'))}: {msg}"
    sys.stdout.write(CF(msg + Style.RESET_ALL))
    sys.stdout.flush()
    if msg[-1] == "\n":
        plaintext = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', msg)
        if logh:
            logh.write(plaintext)
            logh.flush()

def print_banner():
    print(CF(r" ____ "))
    print(CF(r"|  _  \ ___ ___ _ _ _ __ ___ _ __ ___ _ _    __ "))
    print(CF(r"| | | |/ _ \ / __| | | | '_ \ / __| '__/ _ \| '_ \ "))
    print(CF(r"| |_| | /__ /\__ \ |_| | | | | (__| | | (_) | | | | |"))
    print(CF(r"|____/ \___||___/ \__, |_| |_|\___|_|  \___/|_| |_|"))
    print(CF(r"                   |___/ "))

def get_args():
    parser = argparse.ArgumentParser(description='Desyncr Command-Line Tool')
    parser.add_argument('-c', '--configfile', type=str, help='Config file name')
    parser.add_argument('-t', '--target', type=str, help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, help='Target port', default=443)
    parser.add_argument('-s', '--ssl', action='store_true', help='Use SSL')
    parser.add_argument('-v', '--vhost', type=str, help='Virtual Host', default="")
    parser.add_argument('-T', '--timeout', type=int, help='Timeout in seconds', default=5)
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (no stdout)')
    parser.add_argument('-e', '--exit-early', action='store_true', help='Exit early upon finding a vulnerability')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    print_banner()
    args = get_args()
    configfile = args.configfile
    smhost = args.target
    smport = args.port
    SSLFlag = args.ssl
    logh = None
    desyncr = Desyncr(configfile, smhost, smport, SSLFlag=SSLFlag, logh=logh, smargs=args)
    desyncr.run()
