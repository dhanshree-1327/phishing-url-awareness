
# Phishing URL Checker

## 1. Project Overview

Phishing URL Checker is a Python-based cybersecurity mini-project
that analyzes URLs for potentially suspicious characteristics.

The program uses rule-based analysis to calculate a heuristic
risk score and display warnings that may help users recognize
potentially deceptive URLs.

It is an educational tool and does not guarantee that a URL is
safe or malicious.

## 2. Objectives

- Understand common characteristics of suspicious URLs.
- Identify potentially misleading URL patterns.
- Calculate a risk score from 0 to 100.
- Display clear explanations for detected indicators.
- Analyze one URL or multiple URLs.
- Export scan results to a CSV report.
- Practise Python programming and basic cybersecurity concepts.

## 3. Features

- Risk score and risk category.
- Detection of URLs containing the @ symbol.
- Detection of unusually long URLs.
- Detection of IP-address hostnames.
- Detection of excessive subdomains.
- Detection of punycode domain labels.
- Detection of HTTP URLs.
- Detection of known URL-shortening services.
- Detection of selected suspicious hostname words.
- Detection of multiple percent-encoded sequences.
- Input validation and error handling.
- Batch URL scanning.
- CSV report export.

## 4. Technologies Used

- Python 3
- Visual Studio Code
- Python standard library
- CSV for exporting scan results
- Git and GitHub for version control and project sharing

## 5. Project Structure

phishing-url-awareness/
├── phishing_checker.py
├── README.md
├── requirements.txt
├── scan_results.csv
└── tests/
    └── test_phishing_checker.py

The CSV report is generated when the user exports results.

## 6. Requirements

- Python 3.10 or later recommended.
- Visual Studio Code or another Python editor.
- Windows, Linux, or macOS.

No third-party Python packages are required.

## 7. How to Run

1. Install Python.
2. Download or clone this project.
3. Open the project folder in Visual Studio Code.
4. Open a terminal in the project folder.
5. Run the following command:

   python phishing_checker.py

6. Select an option from the menu.
7. Enter a URL or scan multiple URLs.
8. Export results to CSV if required.

## 8. Example Test Cases

| Test input | Expected indicator |
|---|---|
| https://www.example.com/login | No current rules should trigger |
| http://192.0.2.10/account | IP address and HTTP |
| https://xn--example.invalid/ | Punycode |
| http://bit.ly/example | URL shortener and HTTP |
| An empty input | Input validation message |

Actual results may depend on the implemented rules.

## 9. Risk Score

The program assigns points to selected URL characteristics.
The total score is capped at 100.

- Low: 0–29
- Medium: 30–59
- High: 60–100

These thresholds are heuristic and are not calibrated probabilities
of a URL being malicious.

## 10. Limitations

- The program does not open or visit websites.
- It does not verify website ownership or reputation.
- It does not use a machine-learning model.
- It does not automatically confirm phishing.
- Legitimate URLs may trigger warnings.
- Malicious URLs may not trigger any warnings.
- URL-shortener detection does not reveal the final destination.

## 11. Future Enhancements

- Develop a web interface using Streamlit.
- Add automated unit tests.
- Add visual charts and statistics.
- Integrate a reputable threat-intelligence API.
- Generate downloadable PDF reports.
- Improve detection using carefully evaluated datasets.

## 12. Ethical Use

This project is intended for cybersecurity education and
awareness. It analyzes URL text and should not be treated as a
replacement for professional security tools.

Do not submit confidential URLs to third-party services without
understanding their privacy policies.

## 13. Author

Name: Dhanshree D Gundlekar
Course: Bachelor of Computer Applications (BCA)
Project: Phishing URL Checker
Date: 31st Oct,2026
