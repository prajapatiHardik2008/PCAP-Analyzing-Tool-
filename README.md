# 🧪 PCAP Analyzer (CTF Style)

## 📌 Description

PCAP Analyzer (CTF Style) ek Python-based tool hai jo **.pcap (packet capture) files** ko analyze karta hai. Ye project specially **CTF (Capture The Flag)** challenges ke liye design kiya gaya hai, jahan flags network traffic ke andar hidden hote hain.

Tool Scapy library ka use karke network packets ko read karta hai aur unme se important information extract karta hai jaise:

* Source & Destination IP addresses
* Network protocols (TCP / UDP / ICMP)
* Packet payload ke andar readable strings
* User-defined ya default flag format ke basis par possible flags

Agar flag galat ho ya na mile, tab bhi tool **saara readable data print karta hai**, taaki analyst manually investigate kar sake — bilkul real CTF tools ki tarah.

---

## 🎯 Features

* 📂 PCAP file load & verify
* 🌐 Sabhi unique IP addresses extract karta hai
* 📡 Used network protocols identify karta hai
* 🚩 User-input ya default flag format se flag search karta hai
* 🧵 Packet payload se saare readable strings nikalta hai
* ❌ Flag na mile tab bhi useful output deta hai (no early exit)

---

## 🛠️ Requirements

* Python 3.x
* Scapy library

Install Scapy:

```bash
pip install scapy
```

---

## ▶️ How to Run

1. PCAP file ko project folder me rakho (example: `test_flag.pcap`)
2. Script run karo:

```bash
python analyzer.py
```

3. Jab prompt aaye, apna flag format enter karo (example: `flag` or `picoCTF`)

   * Agar blank chhoda, to default `flag` use hoga

---

## 📤 Output

Tool sequentially ye output deta hai:

1. Total packets count
2. All unique IP addresses
3. Detected network protocols
4. Possible flags (agar mile)
5. Sabhi readable strings from packet payloads

---

## 🧠 CTF Use Case

* Hidden flags in TCP streams
* Suspicious readable data analysis
* Network forensics basics
* Wireshark ke sath Python automation

---

## 📄 Resume Line (Optional)

**Developed a Python-based PCAP Analyzer using Scapy to extract IP addresses, protocols, and hidden CTF flags from network traffic.**

---

## ⚠️ Disclaimer

Ye tool **sirf educational aur CTF practice** ke liye hai. Real-world networks par bina permission use karna illegal ho sakta hai.

---

Happy Hacking 🚀 (Ethically 😄)
