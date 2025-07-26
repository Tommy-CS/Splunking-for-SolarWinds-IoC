# Splunking for SolarWinds IoC
This project documents my work on **Project 7** of CodePath's CYB102 course, where I investigated a SolarWinds-related cyber threat using **Splunk**, **VirusTotal**, and threat hunting techniques.

## Overview
The goal of this project was to simulate threat hunting and incident analysis by:
- Ingesting real-world IOC data related to the **SolarWinds breach**
- Analyzing network logs to identify matches
- Researching IOCs using **VirusTotal**
- Building a Splunk dashboard to visualize potential threats
- Applying event correlation and threat intelligence principles

## Tools Used
- **Splunk**
- **VirusTotal**
- **SolarWindsIOCs.csv** (threat intel source)
- **NetworkProxyLog02.csv** (log data for analysis)

---

## Matches Found

### ✅ Match #1
- **Matched IP:** `13.59.205.66`  
- **Date & Time:** `03-04-2024 06:57:28`  
- **Computer Name:** `WS-SolarWave-212`
- **Splunk Findings:**
  <img src="https://github.com/user-attachments/assets/a4e6e150-fd84-4b25-a5ef-2f83613deb2c">

- **VirusTotal Result:** 
  <img src="https://github.com/user-attachments/assets/c0053c93-441b-427f-8c11-6d5764ec3eb2" width="600"/>

---

### ✅ Match #2
- **Matched IP:** `5.252.177.25`  
- **Date & Times:**
  - `03-03-2024 07:04:28`
  - `03-05-2024 07:11:28`
  - `03-05-2024 07:37:28`  
- **Computer Names:**
  - `LN-SolarStrike-14`
  - `MX-SolarStorm-136`
  - `WS-SolarLight-943`
- **Splunk Findings:**
  <img src="https://github.com/user-attachments/assets/7229ef86-cba5-40c6-be75-2470358fb991">
- **VirusTotal Result:**
  <img src="https://github.com/user-attachments/assets/bb520859-47d1-476d-bea4-bc148dc9c6ba" width="600"/>

---

### ✅ Match #3
- **Matched IP:** `54.215.192.52`  
- **Date & Time:** `03-05-2024 07:10:28`  
- **Computer Name:** `LN-SolarShadow-552`  
- **Splunk Findings:**
  <img src="https://github.com/user-attachments/assets/94b642f6-f9cb-407e-8447-878b93c5d912">

- **VirusTotal Result:**  
  <img src="https://github.com/user-attachments/assets/876f0e93-51d0-4d8c-82fb-55a4e7c3da6d" width="600"/>

---

## 📊 Splunk Dashboard Query

```spl
(source="SolarWindsIOCs.csv" OR source="networkproxylog02.csv") 
| stats values(source) as sources, values("Computer Name") as ComputerName, values(Date) as Date, values(Time) as Time by "IP Address"
| where mvcount(sources) > 1
| table "IP Address", ComputerName, Date, Time
