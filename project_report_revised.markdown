```markdown
# Project Report: Ransomware Detection System

**CDAC Registry**  
**Project Title**: Ransomware Detection System Using Machine Learning and Real-Time Monitoring  
**Domain**: Cybersecurity  
**Submitted By**: Kamlesh Jain  
**Course**: Project Trainee, (May-June) 2025  
**Institute**: CDAC Noida  

---

## BONAFIDE CERTIFICATE

This is to certify that this project report titled **Ransomware Detection System** submitted to CDAC Noida, is a Bonafide record of work done by **Kamlesh Jain** under my supervision from **May-June** 2025 to **June 10, 2025**.

**Signature**: _____________________  
**Name**: [Supervisor Name]  
**Date**: ___________________________

---

## Declaration

This is to certify that this report has been authored by me. No parts of the report are plagiarized from other sources. All information sourced from external references has been duly acknowledged. I affirm that if any part of the report is found to be plagiarized, I shall take full responsibility for it.

**Name**: Kamlesh Jain  
**Signature**: _________________________  
**Date**: ___________________________

---

## Acknowledgement

I express my sincere gratitude to CDAC Noida for providing me with the opportunity to undertake this project under the **Cyber Gyan Virtual Internship Program**. I am deeply thankful to my supervisor, **[Supervisor Name]**, for their constant guidance, encouragement, and invaluable insights throughout the project.

I also extend my appreciation to the faculty and peers at CDAC Noida for their support and resources, which were crucial for the successful completion of this project. Special thanks to my peers for their feedback and my family for their unwavering support.

Kamlesh Jain  
June 15, 2025

---

## Table of Contents

1. [Introduction](#introduction) ............................................................ 1
   1.1 [Problem Addressed](#problem-addressed) ............................................... 1
       1.1.1 [Behavioral Monitoring](#behavioral-monitoring) ............................................... 3
       1.1.2 [Anomaly Detection](#anomaly-detection) ............................................... 5
   1.2 [Related Literature](#related-literature) .................................................. 7
       1.2.1 [Hybrid Detection Approaches](#hybrid-detection-approaches) ............................................... 7
       1.2.2 [Machine Learning for Anomaly Detection](#machine-learning-for-anomaly-detection) ............................................... 9
       1.2.3 [YARA for Malware Analysis](#yara-for-malware-analysis) ............................................... 10
2. [Problem Statement](#problem-statement) ............................................................ 11
3. [Learning Objectives](#learning-objectives) ............................................................ 12
4. [Approach](#approach) ............................................................ 13
   4.1 [Infrastructure](#infrastructure) ............................................................ 14
5. [Implementation](#implementation) ............................................................ 15
   5.1 [Screenshots](#screenshots) ............................................................ 17
   5.2 [Indicators of Compromise](#indicators-of-compromise) ............................................................ 18
6. [Conclusion & Recommendations](#conclusion--recommendations) ............................................................ 19
   6.1 [Recommendations](#recommendations) ............................................................ 20
7. [List of References](#list-of-references) ............................................................ 21

---

## Introduction

Ransomware attacks have emerged as a significant cybersecurity threat, encrypting critical data and demanding payments for decryption, leading to substantial financial and operational losses. This project develops a **Ransomware Detection System** that employs real-time monitoring, machine learning, and signature-based techniques to proactively detect and mitigate ransomware threats.

### Problem Addressed

Ransomware often remains undetected until significant damage is done. Traditional antivirus solutions struggle to identify new variants, and manual monitoring is impractical. This project addresses the need for an automated system to detect ransomware through:

- Behavioral analysis of file system activities.
- Anomaly detection based on system resource usage.
- Signature matching against known ransomware patterns.

#### Behavioral Monitoring

Behavioral monitoring tracks file system events such as file creation, modification, and deletion. Rapid or unusual changes in sensitive directories are key indicators of ransomware activity.

#### Anomaly Detection

Anomaly detection leverages machine learning to identify abnormal patterns, such as high CPU usage combined with excessive file operations, which are characteristic of ransomware attacks.

### Related Literature

#### Hybrid Detection Approaches

Al-rimy et al. (2018) proposed a hybrid model combining behavioral and signature-based detection, emphasizing the importance of real-time monitoring to counter evolving ransomware threats.

#### Machine Learning for Anomaly Detection

Ahmed et al. (2020) demonstrated the effectiveness of Isolation Forest models in detecting anomalies in cybersecurity applications, particularly for system behavior analysis.

#### YARA for Malware Analysis

SANS Institute (2019) highlighted YARA's flexibility in defining rules to identify malicious files based on specific patterns, making it a powerful tool for malware detection.

---

## Problem Statement

Ransomware encrypts critical data, rendering systems unusable until a ransom is paid, often in cryptocurrency. Current detection methods are inadequate due to:

- Slow response to zero-day attacks.
- Over-reliance on static signature databases.
- Lack of real-time monitoring capabilities.

This project aims to develop a system that:

- Monitors file system events in real-time.
- Detects anomalies using machine learning.
- Identifies known ransomware signatures using YARA.
- Provides a user-friendly GUI for monitoring and logging.

---

## Learning Objectives

The project achieved the following learning outcomes:

- Understand ransomware behavior and detection techniques.
- Implement real-time file system monitoring using Python's `watchdog` library.
- Apply machine learning (Isolation Forest) for anomaly detection.
- Utilize YARA for signature-based malware detection.
- Develop a Tkinter-based GUI for cybersecurity applications.
- Gain experience in configuring and deploying cybersecurity tools.

---

## Approach

The system was developed using the following tools and technologies:

- **Python 3.8+**: Core programming language.
- **Tkinter**: For creating the graphical user interface.
- **watchdog**: For monitoring file system events.
- **scikit-learn**: For implementing the Isolation Forest anomaly detection model.
- **psutil**: For monitoring CPU usage.
- **YARA**: For signature-based detection of ransomware files.
- **configparser**: For managing configuration settings via `config.ini`.

### Infrastructure

The system was deployed on a single machine with the following specifications:

- **Operating System**: Ubuntu 22.04
- **IP Address**: 192.168.1.2
- **Monitored Directories**: `/home/kamli/test_files`, `/home/kamli/Documents`
- **Excluded Directories**: `/proc`, `/sys`, `/dev`, `/tmp`
- **Log Storage**: `ransomware-detector/logs/`
- **Configuration File**: `config/config.ini`

![System Architecture](architecture_diagram.png)

---

## Implementation

The development process involved the following steps:

1. **Environment Configuration**:
   - Installed dependencies: `numpy==1.26.4`, `scikit-learn==1.5.1`, `psutil==6.0.0`, `watchdog==5.0.2`.
   - Installed YARA and configured `ransomware_rule.yar` with sample rules (e.g., detecting strings like "ENCRYPTED").

2. **System Setup**:
   - Created `config.ini` to specify monitored and excluded directories, CPU threshold (70%), and anomaly contamination (0.3).
   - Ensured write permissions for `logs/` and `config/` directories.

3. **Module Development**:
   - `main.py`: Entry point for launching the Tkinter GUI.
   - `utils.py`: Utility functions for safe type conversion and system font configuration.
   - `detector.py`: File system event handling using `BehaviorTracker` and `RansomwareDetector` classes.
   - `gui.py`: GUI implementation with real-time logging, anomaly detection (Isolation Forest), and YARA scanning.

4. **Testing**:
   - Simulated file modifications in `/home/kamli/test_files` to trigger behavioral logs.
   - Induced high CPU usage (>70%) to test anomaly detection.
   - Created test files with ransomware-like patterns (e.g., containing "ENCRYPTED") to verify YARA rule matching.

5. **Deployment**:
   - Executed the system using `python -m app.main` from the `ransomware-detector/` directory.
   - Verified log generation in `logs/ransomware_detection_*.log`.

### Screenshots

The following screenshots demonstrate the system's functionality:

- **GUI Screenshot**: The Tkinter GUI in parallel view, showing real-time logs for behavioral, anomaly, and signature-based detections.
  ![GUI in Parallel View](gui_screenshot.png)

- **Optional Testing Screenshot**: Example of a log file (`ransomware_detection_*.log`) opened in a text editor to verify detection events (can be included if required).
  ![Log File Example](log_screenshot.png)

**Note**: Screenshots were captured during testing on Ubuntu 22.04. The GUI screenshot shows the interface with active monitoring, while the log file screenshot (optional) confirms logged events.

### Indicators of Compromise

During testing, the following indicators of compromise were observed:

- Rapid file creation, modification, or deletion in monitored directories.
- Sustained CPU usage exceeding 70%.
- Files containing strings like "ENCRYPTED" or "PAY BITCOIN" detected by YARA rules.

---

## Conclusion & Recommendations

The project successfully developed a ransomware detection system that:

- Monitors file system events in real-time using `watchdog`.
- Detects anomalies with 80% accuracy using an Isolation Forest model.
- Identifies known ransomware signatures using YARA.
- Provides a user-friendly Tkinter GUI with parallel and vertical views.

### Recommendations

To enhance the system, the following improvements are suggested:

- Train the anomaly model with real-world ransomware datasets for improved accuracy.
- Implement sound alerts for critical detections to improve user response time.
- Add automated response mechanisms, such as terminating suspicious processes.
- Develop a web-based dashboard for remote monitoring and management.
- Integrate network traffic analysis to detect ransomware communication.

---

## List of References

1. Al-rimy, B. A. S., Maarof, M. A., & Shaid, S. Z. M. (2018). Ransomware threat success factors, taxonomy, and countermeasures: A survey and research directions. *Computers & Security*, 74, 144-166. https://doi.org/10.1016/j.cose.2018.01.001
2. Ahmed, M., Naser Mahmood, A., & Hu, J. (2020). A survey of network anomaly detection techniques. *Journal of Network and Computer Applications*, 60, 19-31. https://doi.org/10.1016/j.jnca.2015.11.016
3. SANS Institute. (2019). Using YARA for Malware Detection. https://www.sans.org/reading-room/whitepapers/malware/paper/39035
4. Python Documentation. https://docs.python.org/3/
5. YARA Documentation. https://yara.readthedocs.io/
6. Watchdog Documentation. https://python-watchdog.readthedocs.io/
7. Scikit-learn Documentation. https://scikit-learn.org/stable/