# ThreatWatch 
### AI-Assisted SOC Log Anomaly Detection & Threat Intelligence Dashboard  

🚀 Live Demo: https://rogkb32rhi5lto8qcu2x4f.streamlit.app

---

## 📌 Overview  

ThreatWatch is a Security Operations Center (SOC)-inspired dashboard that monitors system logs, detects suspicious behavior, and visualizes cyber threats in real time.

It combines rule-based detection with machine learning (Isolation Forest) to identify anomalies such as brute-force attacks and data exfiltration.

---

## 🎯 Features  

- Simulated real-time log generation  
- CSV-based log ingestion  
- AI-based anomaly detection (Isolation Forest)  
- Rule-based threat detection  
- Dynamic threat scoring per IP  
- Interactive dashboard with:
  - Overview metrics  
  - Logs view  
  - Activity graphs  
  - Attack distribution  
  - Threat ranking  
  - Geo visualization (demo)  

---

## 🛠️ Tech Stack  

- Streamlit  
- Pandas  
- Scikit-learn  
- Altair  
- PyDeck  

---

## ⚙️ Setup  

1. Clone the repository  

git clone https://github.com/ananya05verma/ThreatWatch.git  
cd ThreatWatch

2. Install dependencies  

pip install -r requirements.txt  

3. Run the app  

streamlit run app.py  

---

## 📂 CSV Format  

ip,action,timestamp  
192.168.1.1,LOGIN_FAILED,2026-04-25 10:00:00  
10.0.0.5,DATA_DOWNLOAD,2026-04-25 10:00:05  

---

## 🧠 How It Works  

- Logs are ingested (simulated or CSV)  
- Features are extracted (failed logins, downloads, frequency)  
- Isolation Forest detects anomalies  
- Rule-based logic detects known attack patterns  
- Threat scores are calculated per IP  
- Results are displayed in a SOC-style dashboard  

---

## 📈 Future Improvements  

- Real-time log integration  
- Real GeoIP mapping  
- Advanced ML models  
- Alert notifications  

---

## 👩‍💻 Author  

Ananya Verma  
B.Tech CSE | Cybersecurity & Full Stack Enthusiast  

---

## ⭐ Inspiration  

Inspired by real-world SIEM tools like Splunk and IBM QRadar  
