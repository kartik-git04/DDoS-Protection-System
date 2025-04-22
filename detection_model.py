import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
from sklearn.preprocessing import MinMaxScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, f1_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Bidirectional
from tensorflow.keras.callbacks import ReduceLROnPlateau, EarlyStopping
import smtplib
from email.message import EmailMessage
import ssl

# =======================
# 1️⃣ Load and Preprocess Dataset
# =======================
csv_file_path = r"/home/kartik/dti/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
df = pd.read_csv(csv_file_path, low_memory=False)
df.columns = df.columns.str.strip()

# Select numeric columns and fill missing values
numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
df = df[numeric_cols].fillna(0)

# Select first numeric column as target
target_col = numeric_cols[0]
data = df[target_col].values

# Scale data
scaler = MinMaxScaler()
data_scaled = scaler.fit_transform(data.reshape(-1, 1)).flatten()

# =======================
# 2️⃣ Create Sequences
# =======================
def create_sequences(data, seq_length):
    sequences = []
    for i in range(len(data) - seq_length):
        sequences.append(data[i:i + seq_length])
    return np.array(sequences)

seq_length = 50
X = create_sequences(data_scaled, seq_length)
y = data_scaled[seq_length:]
X = np.expand_dims(X, axis=-1)

# Train-test split
train_size = int(len(X) * 0.8)
X_train, X_test = X[:train_size], X[train_size:]
y_train, y_test = y[:train_size], y[train_size:]

# =======================
# 3️⃣ KNN Model for Anomaly Detection
# =======================
knn = KNeighborsClassifier(n_neighbors=12)
threshold = np.percentile(y_train, 95)
y_train_labels = (y_train > threshold).astype(int)

knn.fit(X_train.reshape(X_train.shape[0], -1), y_train_labels)
y_knn_pred = knn.predict(X_test.reshape(X_test.shape[0], -1))
y_true = (y_test > threshold).astype(int)

# =======================
# 4️⃣ LSTM Model for Anomaly Detection
# =======================
lstm_model = Sequential([
    Bidirectional(LSTM(128, return_sequences=True, activation='tanh'), input_shape=(seq_length, 1)),
    Dropout(0.3),
    Bidirectional(LSTM(64, return_sequences=True, activation='tanh')),
    Dropout(0.3),
    LSTM(32, return_sequences=False, activation='tanh'),
    Dropout(0.3),
    Dense(1, activation='sigmoid')
])

lstm_model.compile(optimizer='adam', loss='mse', metrics=['accuracy'])
reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-5)
early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

y_train_lstm = y_train_labels.reshape(-1, 1)
lstm_model.fit(X_train, y_train_lstm, epochs=10, batch_size=32, validation_split=0.1, callbacks=[reduce_lr, early_stop], verbose=1)

y_lstm_pred_prob = lstm_model.predict(X_test)
y_lstm_pred = (y_lstm_pred_prob > 0.5).astype(int).flatten()

# =======================
# 5️⃣ Metrics
# =======================
knn_accuracy = accuracy_score(y_true, y_knn_pred) * 100
knn_f1 = f1_score(y_true, y_knn_pred) * 100

lstm_accuracy = accuracy_score(y_true, y_lstm_pred) * 100
lstm_f1 = f1_score(y_true, y_lstm_pred) * 100

print("\n📊 Model Evaluation:")
print(f"🔹 KNN Accuracy: {knn_accuracy:.2f}%, F1-Score: {knn_f1:.2f}%")
print(f"🔹 LSTM Accuracy: {lstm_accuracy:.2f}%, F1-Score: {lstm_f1:.2f}%")

# =======================
# 6️⃣ Graph: Actual vs Predicted
# =======================
output_folder = "College_website"
os.makedirs(output_folder, exist_ok=True)

plt.figure(figsize=(12, 6))
plt.plot(y_true, label="Actual Anomalies", alpha=0.7)
plt.plot(y_knn_pred, label="KNN Predicted", linestyle="dashed", alpha=0.7)
plt.plot(y_lstm_pred, label="LSTM Predicted", linestyle="dotted", color='red', alpha=0.7)
plt.xlabel("Data Points")
plt.ylabel("Anomaly (1 = Yes, 0 = No)")
plt.title("📊 Actual vs Predicted Anomalies (KNN & LSTM)")
plt.legend()

graph_path = os.path.join(output_folder, "anomaly_graph.png")
plt.savefig(graph_path)
print(f"[✔] Anomaly graph saved to: {graph_path}")
plt.show()

# =======================
# 7️⃣ Extract & Save Anomalies
# =======================
anomalies = pd.DataFrame({
    "Index": np.arange(len(y_true)),
    "Actual_Anomaly": y_true,
    "KNN_Predicted": y_knn_pred,
    "LSTM_Predicted": y_lstm_pred
})

detected_anomalies = anomalies[(anomalies['KNN_Predicted'] == 1) | (anomalies['LSTM_Predicted'] == 1)]
anomalies_csv_path = os.path.join(output_folder, "anomalies_detected.csv")
detected_anomalies.to_csv(anomalies_csv_path, index=False)
print(f"[✔] Anomalies saved to: {anomalies_csv_path}")

# =======================
# 8️⃣ Identify Anomaly IPs
# =======================
full_df = pd.read_csv(csv_file_path, low_memory=False)
full_df.columns = full_df.columns.str.strip()

if 'Source IP' in full_df.columns:
    full_df['Anomaly'] = 0
    anomaly_indices = detected_anomalies['Index'] + seq_length
    valid_indices = anomaly_indices[anomaly_indices < len(full_df)]
    full_df.loc[valid_indices, 'Anomaly'] = 1

    anomaly_ips = full_df[full_df['Anomaly'] == 1]['Source IP'].value_counts().reset_index()
    anomaly_ips.columns = ['IP Address', 'Count']

    ip_csv_path = os.path.join(output_folder, "anomaly_ips.csv")
    anomaly_ips.to_csv(ip_csv_path, index=False)
    print(f"[✔] Anomaly IPs saved to: {ip_csv_path}")
else:
    print("[!] 'Source IP' column not found in the dataset.")
    ip_csv_path = None

# =======================
# 9️⃣ Send Email with Anomalous IPs
# =======================
if ip_csv_path:
    sender_email = "xyz@gmail.com" 
    receiver_email = "zyx@gmail.com"
    subject = " Detected Anomalous IPs"
    body = "Hi,\n\nPlease find attached the list of detected anomalous IPs.\n\nRegards,\nSecurity System"
    password = "your_app_password"  

    msg = EmailMessage()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.set_content(body)

    with open(ip_csv_path, 'rb') as file:
        msg.add_attachment(file.read(), maintype='application', subtype='octet-stream', filename="anomaly_ips.csv")

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print("[✔] Email sent with anomaly IPs attached.")
    except Exception as e:
        print(f"[❌] Failed to send email: {e}")

