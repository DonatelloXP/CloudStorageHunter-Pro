<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/06432b82-c4a0-4f27-8dbf-b7104205fe9b" />

# 🔥 CloudStorageHunter-Pro

> 🚀 Ultimate Cloud Storage Security Assessment & Reconnaissance Tool

---

## 🧠 Overview

**CloudStorageHunter-Pro** is a powerful, multi-threaded security tool designed for discovering, analyzing, and testing misconfigured cloud storage buckets across multiple providers.

It combines **reconnaissance, vulnerability scanning, credential extraction, and exploitation testing** into a single advanced GUI-based application.

---

## ✨ Key Features

### 🔍 Discovery & Recon

* Multi-provider support (AWS S3, Google GCS, Azure, etc.)
* Smart bucket name generation & enumeration
* DNS-based discovery techniques
* Custom wordlist support

### 📦 Bucket Analysis

* Detect public/private permissions
* Identify misconfigurations
* Risk scoring system (Low / Medium / High / Critical)
* Bucket metadata extraction

### 📁 Advanced File Manager

* Browse files in a tree structure
* Upload / Download / Delete files
* Built-in file editor
* Search & filter files instantly

### 🔐 Credential & Data Extraction

* Detect API keys, tokens, passwords
* Extract emails, URLs, IPs
* Identify sensitive files (.env, backups, configs)
* Pattern-based scanning engine

### 💣 Vulnerability Testing

* XSS (Cross-Site Scripting)
* SQL Injection
* LFI / RFI
* RCE (Remote Code Execution)
* SSRF (Server-Side Request Forgery)
* Open Redirect

### ⚡ Performance

* Multi-threaded scanning engine
* High-speed enumeration
* Optimized request handling

### 📊 Reporting

* HTML Reports
* CSV Export
* JSON Export
* Executive summaries

### 🛠️ Built-in Tools

* Hash Generator (MD5 / SHA1 / SHA256)
* Base64 Encoder/Decoder
* URL Encoder/Decoder
* Regex Tester
* Password Generator
* Network & Port Scanner

---

## 🖥️ Screenshots

<img width="1909" height="985" alt="image" src="https://github.com/user-attachments/assets/72d28cfa-bad5-4bed-accb-f9f9e0900494" />
<img width="1918" height="960" alt="image" src="https://github.com/user-attachments/assets/da198b88-4cc2-479f-9c10-a7b587270b11" />
<img width="1914" height="958" alt="image" src="https://github.com/user-attachments/assets/31326797-42d3-449b-9b67-f01563e25719" />

* Dashboard
* File Manager
* Scan Results
* Credentials Panel

---

## ⚙️ Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/DonatelloXP/CloudStorageHunter-Pro.git
cd CloudStorageHunter-Pro
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python BM_V14.py
```

---

## 📦 Requirements

* Python 3.9+
* Internet connection (for scanning)

### 📚 Dependencies

```txt
requests
cryptography
dnspython
```

---

## 📁 Project Structure

```
CloudStorageHunter-Pro/
│
├── BM_V14.py              # Main application
├── README.md             # Documentation
├── requirements.txt      # Dependencies
├── results/              # Scan outputs
└── database/             # SQLite database
```

---

## ⚡ How It Works

1. Enter a target domain or keyword
2. Tool generates potential bucket names
3. Performs multi-provider scanning
4. Analyzes permissions and files
5. Extracts sensitive data
6. Generates reports and risk scores

---

## 🔐 Security Capabilities

* Detect exposed cloud storage
* Identify sensitive data leaks
* Analyze access permissions
* Perform controlled vulnerability testing
* Assist in penetration testing workflows

---

## ⚠️ Disclaimer

> 🚨 This tool is for **educational purposes and authorized security testing only**

* Do NOT use this tool on systems you do not own or have permission to test
* Unauthorized usage may violate laws and regulations
* The author is NOT responsible for misuse or damages

---

## 🧑‍💻 Author

Developed for advanced security research and penetration testing.

Version: **13.0 Ultimate Edition**

---

## 🏷️ Topics (Add in GitHub)

```
cybersecurity
cloud-security
aws
s3
gcs
azure
pentesting
reconnaissance
security-tools
bugbounty
osint
```

---

## ⭐ Support

If you find this project useful:

* ⭐ Star the repository
* 🍴 Fork it
* 🧠 Contribute improvements

---

## 🚀 Future Improvements

* Web-based interface (Django + React)
* API integration
* Real-time scanning dashboard
* AI-based risk analysis

---

## 🤝 Contributing

Pull requests are welcome.
For major changes, please open an issue first.

---

## 📬 Contact

For suggestions or improvements, feel free to reach out.

---

🔥 *Built for hackers, security researchers, and professionals.*
