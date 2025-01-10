# Web Application Fuzzer Tool

## 🚀 Project Overview

This is a **Comprehensive Web Application Fuzzer** developed as part of **Smart India Hackathon 2024 (SIH)**. The project addresses the **SIH Problem Statement ID: SIH1750** under the **Miscellaneous Theme**. Our tool aims to automate web application security testing by integrating popular tools such as OWASP ZAP, Sqlmap, Nmap, and others, providing a unified GUI interface for developers and security teams.

> **Status:** Shortlisted Team (Waiting List Rank 1)  
> **Team Name:** AlgoOptimizers  
> **Team ID:** 15285  

## 🎯 Problem Statement

The goal was to create a cross-platform **Web Application Fuzzer** that detects vulnerabilities in web applications, APIs, and networks, while offering features like:
- **Subdomain Enumeration**
- **Vulnerability Detection**
- **Dependency Testing**
- **Unified Reporting**

This tool enables **early vulnerability detection**, strengthens DevSecOps pipelines, and ensures compliance with standards like OWASP, GDPR, and HIPAA.

---

## 🛠️ Features

1. **Modular Architecture:**  
   Integrates multiple open-source tools for comprehensive security testing:
   - **Subdomain Enumeration:** OWASP Amass
   - **Vulnerability Scanning:** OWASP ZAP, OpenVAS, Arachni
   - **SQL Injection Detection:** Sqlmap
   - **Fuzzing:** Wfuzz
   - **Network Scanning:** Nmap
   - **Dependency Scanning:** Snyk
   - **API Testing:** Postman
   - **Exploit Testing:** Metasploit
   - **Web App Testing:** OWASP Juice Shop

2. **Cross-Platform Compatibility:**  
   Runs on **Linux**, **macOS**, and **Windows**.

3. **Graphical User Interface (GUI):**  
   Developed using `Tkinter` for easy interaction.

4. **Unified Reporting:**  
   Saves scan results as **JSON reports** for easy sharing and actionable insights.

5. **Customizability:**  
   The modular architecture allows easy addition or removal of tools.

6. **Compliance:**  
   Supports OWASP Top 10, GDPR, and HIPAA compliance testing.

---

## 📋 Current Limitations and Known Issues

1. **Dependency Assumptions:**
   - All external tools must be pre-installed and configured correctly.
   - Missing tools or misconfigurations result in failures during scans.

2. **Incomplete Commands:**
   - Some commands (e.g., `arachni --scan target`) are placeholders and need refinement for production use.

3. **Simplistic Vulnerability Marking:**
   - Relies on keyword detection (e.g., "vulnerable" or "vulnerability") in tool outputs, which may lead to false positives or missed vulnerabilities.

4. **Wordlist Dependency:**
   - Fuzzing (`Wfuzz`) requires a `wordlist.txt` file, which is not included in the project.

5. **Limited Validation:**
   - No validation of target URLs before initiating scans.

6. **Performance Overhead:**
   - Scanning large applications may cause delays, especially when multiple tools are selected.

---
## 🔧 How to Contribute

### Step 1: Clone the Repository

```bash
git clone https://github.com/AlgoOptimizers/WebAppFuzzer.git
cd WebAppFuzzer
```

### Step 2: Install Dependencies

Ensure the following tools are installed and accessible from your PATH:
- [Amass](https://owasp.org/www-project-amass/)
- [OWASP ZAP](https://owasp.org/www-project-zap/)
- [Sqlmap](http://sqlmap.org/)
- [Wfuzz](https://github.com/xmendez/wfuzz)
- [Nmap](https://nmap.org/)
- [Metasploit](https://www.metasploit.com/)
- [Postman](https://www.postman.com/)
- [Snyk](https://snyk.io/)
- [OpenVAS](https://www.openvas.org/)
- [Arachni](https://github.com/Arachni/arachni)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

### Step 3: Run the Tool

```bash
python3 main.py
```

### Step 4: Suggest Fixes or Features

- Fork the repository, implement your fixes or features, and submit a pull request.
- Mention specific issues you're addressing and provide a description of your changes.

---

## ⚙️ Technical Details

### Tools and Frameworks
- **Programming Language:** Python
- **Frameworks:** Tkinter (GUI), Subprocess (Tool Integration)
- **Database:** SQLite or MongoDB (future enhancement)

### Challenges Addressed
1. **Early Vulnerability Detection:**  
   Detects vulnerabilities before production deployment.
2. **Unified Reporting:**  
   Actionable insights for faster development cycles and improved security.
3. **Compliance and Standards:**  
   Identifies compliance issues with OWASP, GDPR, HIPAA.

### Flowchart:  
[View Flowchart](https://fuzzer-flowchart.netlify.app/)

---

## 💡 Suggestions for Improvement

1. **Validation Enhancements:**
   - Validate URLs before scans to prevent invalid inputs.
2. **Command Refinements:**
   - Update placeholder commands for tools like Arachni and Juice Shop.
3. **Error Handling:**
   - Improve error messages when tools are not installed or misconfigured.
4. **Advanced Parsing:**
   - Use regex or libraries to parse outputs more effectively.
5. **Include Wordlists:**
   - Provide a default `wordlist.txt` for fuzzing.
6. **Documentation:**
   - Include detailed setup instructions for tools.

---

## 🌟 Project Recognition

This project was submitted to **SIH 2024** and received positive feedback for its **comprehensive approach** and **modular architecture**. Although shortlisted, the team is currently **ranked 1st on the waiting list**.

---

## 📜 References

1. [OWASP Amass](https://owasp.org/www-project-amass/)  
2. [OWASP ZAP](https://owasp.org/www-project-zap/)  
3. [Sqlmap](http://sqlmap.org/)  
4. [Nmap](https://nmap.org/)  
5. [Snyk](https://snyk.io/)  
6. [Metasploit](https://www.metasploit.com/)  
7. [Postman](https://www.postman.com/)  
8. [Arachni](https://github.com/Arachni/arachni)  
9. [OpenVAS](https://www.openvas.org/)  
10. [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

---

## 📽️ Demo

Check out the prototype demo:  
[YouTube Demo Link](https://youtu.be/MX61rFGxQ5w)

---
