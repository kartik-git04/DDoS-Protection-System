The DDoS Protection System is a real-time intrusion detection solution that captures live network packets, analyzes them for anomalies using machine learning models (KNN and LSTM), and automatically flags suspicious IPs. These IPs are both notified to the admin via email and mitigated through the system. A web-based dashboard provides a visual interface for monitoring packet activity and detected threats.


Features
 Live Packet Capture using PyShark

 Anomaly Detection using:

K-Nearest Neighbors (KNN)

Long Short-Term Memory (LSTM) Neural Network

Automatic Email Alerts to the admin with detected malicious IPs

IP Mitigation functionality

Dashboard UI showing:

Captured network packets

Anomaly detection graphs

Model Trained on CICDDoS2019 Dataset


Tech Stack
Python (PyShark, scikit-learn, TensorFlow/Keras)

Machine Learning: KNN, LSTM

Dataset: CICDDoS2019

Frontend: HTML, CSS (for dashboard UI)

Email Service: SMTP-based Python script
