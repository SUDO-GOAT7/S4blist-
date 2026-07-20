🚀 **s4blist- — The Ultimate Subdomain Scanner** 🚀  

🔍 **Discover. Scan. Exploit.**  
`s3blist-` is the next-generation subdomain enumeration tool built for **bug bounty hunters**, **pentesters**, and **security researchers** who want speed, precision, and actionable results — all in one place.  

---

## 🔥 WHAT MAKES IT SPECIAL?

✅ **Hybrid Enumeration** – Combines **crt.sh (passive)** + **smart wordlist (active)** for maximum coverage.  
✅ **Live Check** – Automatically filters out dead subdomains with HTTP/HTTPS status codes.  
✅ **Port Scanning** – Scans top 10 ports (SSH, HTTP, HTTPS, etc.) on every live subdomain.  
✅ **Multi-Format Output** – Saves results in **JSON**, **CSV**, and **HTML** (with embedded screenshots).  
✅ **Lightning Fast** – Uses **threading + concurrent.futures** for parallel scanning.  
✅ **Progress Bar** – Real-time visual feedback with `tqdm`.  
✅ **Colorful CLI** – Easy-to-read output with `colorama`.  
✅ **Zero Dependencies** – Just Python + 3 lightweight libraries.  
## 🎯 Perfect For

- 🎯 Bug Bounty Hunters  
- 🔐 Pentesters  
- 🧠 Security Researchers  
- 📈 Red Teamers  

---

## 🧠 Why s4blist?

- 🔹 Complete recon – from subdomain discovery to port scanning  
- 🔹 Clean, structured output for reports  
- 🔹 Lightweight & portable – works on Termux, Kali, Linux  
- 🔹 Community-ready – easy to extend  

---

## 📌 Roadmap

- [ ] Screenshot support  
- [ ] API integration (SecurityTrails, Shodan)  
- [ ] Slack/Telegram notifications  
- [ ] More output formats (PDF, XML)  

---

## 📄 License

MIT – Free for personal and commercial use.

---

## 🤝 Contribute

Found a bug? Have an idea? Pull requests are welcome.  
Let's build the best subdomain scanner together.

---

## ⭐ Star This Repo

If this tool helped you in your recon or bug bounty journey, **drop a ⭐** to support future development.

---

**Made with ❤️ for the security community.**

Happy Hacking 🚀

---

## ⚡ QUICK START

### 📥 Installation
```bash
git clone https://github.com/SUDO-GOAT7/s4blist-
cd s4blist-
pip install -r requirements.txt
python S4list.py -d example.com -v
