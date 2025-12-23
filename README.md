# Phishing Detector – Rule-Based Security Analysis Tool

## Project Description
This project is a simple rule-based phishing detection system developed in Python.
The goal of the project is to demonstrate common phishing techniques and basic
heuristic methods used to detect potentially malicious URLs and email messages.

The detector analyzes URLs and text content using predefined security rules
and assigns a risk score, which is then used to classify the input as:
SAFE, SUSPICIOUS, or PHISHING.

## Cybersecurity Topics Covered
- Phishing attacks
- Social engineering
- URL analysis
- Heuristic-based detection
- Explainable security analysis

## Detection Methodology
The system uses a rule-based approach instead of machine learning.
Each detected suspicious feature increases the overall risk score.

### URL Analysis
- Use of IP address instead of domain name
- Excessive URL length
- Suspicious characters in URL
- URL shorteners
- Suspicious top-level domains (TLDs)

### Text Analysis
- Presence of phishing-related keywords
- Excessive use of capital letters
- Excessive punctuation
- Embedded links in message content

## Project Structure
phishing_detector/
├── src/
│ ├── url_analyzer.py
│ ├── text_analyzer.py
│ ├── detector.py
│
├── samples/
│ ├── safe_urls.txt
│ ├── phishing_urls.txt
│ ├── phishing_emails.txt
│
├── main.py
└── README.md

## Future Improvements
- Machine learning-based classification
- Levenshtein distance for domain similarity detection
- GUI application
- Integration with real phishing datasets

## Disclaimer
This tool is intended for educational purposes only.
It should not be used as a production security system.
