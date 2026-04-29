# 🛡️ AI Phishing Detection System

## 🚀 Overview

AI Phishing Detection System is an intelligent security solution designed to detect phishing attacks in **URLs, emails, and live websites** using Machine Learning and Natural Language Processing (NLP).

The system is enhanced with a **Chrome Extension** that monitors real-time user activity and flags suspicious content instantly.

---

## 🎯 Features

* 🔍 Detects phishing in URLs and email content
* 🌐 Real-time website monitoring using Chrome Extension
* 🤖 Machine Learning-based classification
* 🧠 NLP-based text analysis for email threats
* ⚡ Fast and efficient API-based detection system

---

## 🧠 How It Works

1. User visits a website or opens an email
2. Extension captures URL/content
3. Data is sent to backend model
4. ML model analyzes patterns and features
5. System returns prediction: **Phishing / Safe**

---

## 🛠️ Tech Stack

* **Language:** Python
* **ML Libraries:** Scikit-learn, Pandas, NumPy
* **NLP:** Text preprocessing & feature extraction
* **Frontend:** JavaScript (Chrome Extension)
* **Backend:** API integration

---

## 📂 Project Structure

AI_Phishing_Detection/
│── model/ # Trained ML models
│── extension/ # Chrome Extension files
│── backend/ # API and detection logic
│── data/ # Dataset
│── main.py # Entry point
│── requirements.txt

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository

```bash
git clone https://github.com/PiYusH9805/AI_Phishing_Detection.git
cd AI_Phishing_Detection
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the backend

```bash
python main.py
```

### 4️⃣ Load Chrome Extension

* Go to Chrome → Extensions
* Enable **Developer Mode**
* Click **Load Unpacked**
* Select the `extension/` folder

---

## 📊 Model Details

* Used classification algorithms for phishing detection
* Feature engineering on URL patterns and email text
* Achieved high accuracy on test dataset

---

## 📸 Future Improvements

* Deploy as a web-based application
* Improve model accuracy with deep learning
* Add real-time threat database integration
* UI enhancements for better user experience

---

## 👨‍💻 Author

**Piyush Sharma**

* GitHub: https://github.com/PiYusH9805

---

## ⭐ Contributing

Contributions are welcome! Feel free to fork and improve the project.

---

## 📜 License

This project is for educational purposes.
