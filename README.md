# PhishArk - Advanced Phishing Toolkit

![PhishArk Logo](https://gitlab.com/arpitxd/phishark/-/raw/main/data/phishark.png)

**PhishArk** is a powerful and advanced phishing tool that supports over **70 website templates**, real-time data capture, Telegram bot integration, custom site support, tunneling via multiple services, and much more.

>**Version**: 1.2.1  
>**Author**: [Arpit Dhameliya](https://github.com/arpitxp), [Zeel Patel](https://gitlab.com/zeelxpatel)  
>**License**: MIT
---

## 🚀 Features

- 🔧 **Around 70 Website Templates**  
- 🛜 Tunneling via:
  - CloudFlared
  - LocalXpose
  - LocalHostRun
  - Serveo
- 📲 Real-time data and IP collection
- 📦 Auto installation of dependencies and modules
- 📥 Telegram bot support for real-time alerts
- 🔐 OTP capture support
- 🪟 GUI-friendly (Rich console with color-coded output)
- 🧠 Smart masking and custom bait links
- 🔧 Compatible with **Termux**, **Linux**, and **macOS**

---

## 📸 Screenshots

![PhishArk Screenshot](https://raw.githubusercontent.com/arpitxp/files/main/phishingsites/assets/phishark-demo.gif)

---

## 📦 Requirements

- Python 3.x
- PHP
- SSH
- pip modules:
  - `requests`
  - `rich`
  - `beautifulsoup4`

---

## 🔧 Installation

```bash
git clone https://gitlab.com/arpitxd/phishark
cd phishark
chmod +x phishark.py
python3 phishark.py
```
## 🔌 Command Line Options
```bash
usage: phishark.py [options]

optional arguments:
  -p, --port         PhishArk's server port (default: 9000)
  -o, --option       Phishing template index number
  -t, --tunneler     Tunneling method (cloudflared, loclx, localhostrun, serveo)
  -r, --region       Region for LocalXpose
  -s, --subdomain    Custom subdomain (Pro feature for LocalXpose)
  -u, --url          Redirection URL after data capture
  -m, --mode         Running mode (test/normal)
  -e, --troubleshoot Test a tunneler
  --nokey            Use SSH tunneling without key (default: False)
  --kshrt            Show shortened kshrt URL (default: False)
  --noupdate         Skip update check (default: False)
```
## ⚙️ How to Use
1. Run the tool:
```bash
python3 phishark.py
```
2. Choose a phishing template from the menu.

3. Send the generated masked URL to your target.

4. Capture login/IP credentials in real-time.

## 🔐 Telegram Bot Integration
To enable real-time alerts:

1. Create a bot on Telegram BotFather

2. Get your chat ID (e.g., via @userinfobot)

3. Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in the script manually or via environment variables.

## ⚠️ Disclaimer
This tool is made for educational purposes only.
Using PhishArk for attacking targets without prior mutual consent is illegal. The developer is not responsible for any misuse.

## 👨‍💻 Credits
Arpit Dhameliya - 
https://gitlab.com/arpitxd

Zeel Patel - 
https://gitlab.com/zeelxpatel

Inspired by: **KasRoudra - PyPhisher**


## 📜 License
This project is licensed under the MIT License.


