import pandas as pd
import re
import pickle
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack

# -------------------------------
# Load Dataset
# -------------------------------
df = pd.read_csv("dataset.csv")
print("Dataset Loaded Successfully")

df = df.dropna(subset=["text_combined", "label"])

# -------------------------------
# Cleaning Function
# -------------------------------
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"[^a-zA-Z0-9 ]", " ", text)
    return text

df["clean_text"] = df["text_combined"].apply(clean_text)

# -------------------------------
# Extra Features (6 Features)
# -------------------------------
def extra_features(text):

    text = str(text)
    text_lower = text.lower()

    url_count = len(re.findall(r"http\S+|www\S+", text))
    email_count = len(re.findall(r"\S+@\S+", text))
    word_count = len(text.split())

    suspicious_words = [
        "verify","update","password","bank","urgent",
        "click","account","login","reset","expire",
        "suspend","disable","confirm","immediately",
        "locked","unauthorized","restricted","otp"
    ]

    suspicious_count = sum(text_lower.count(word) for word in suspicious_words)

    trusted_domains = [
        "google.com","amazon.com","amazon.in",
        "microsoft.com","apple.com","drive.google.com"
    ]

    trusted_flag = any(domain in text_lower for domain in trusted_domains)

    urgency_flag = 1 if word_count < 20 and suspicious_count > 0 else 0

    return [
        url_count,
        email_count,
        word_count,
        suspicious_count,
        int(trusted_flag),
        urgency_flag
    ]

extra_feature_array = np.array(
    df["text_combined"].apply(extra_features).tolist()
)

# -------------------------------
# Train Test Split
# -------------------------------
X_train, X_test, y_train, y_test, extra_train, extra_test = train_test_split(
    df["clean_text"],
    df["label"],
    extra_feature_array,
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

# -------------------------------
# TF-IDF
# -------------------------------
vectorizer = TfidfVectorizer(
    max_features=8000,
    ngram_range=(1, 2),
    stop_words="english"
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# -------------------------------
# Scale Extra Features
# -------------------------------
scaler = StandardScaler(with_mean=False)

extra_train_scaled = scaler.fit_transform(extra_train)
extra_test_scaled = scaler.transform(extra_test)

X_train_final = hstack([X_train_vec, extra_train_scaled])
X_test_final = hstack([X_test_vec, extra_test_scaled])

# -------------------------------
# Train Model
# -------------------------------
model = LogisticRegression(
    class_weight="balanced",
    max_iter=3000
)

print("Training Model...")
model.fit(X_train_final, y_train)
print("Training Complete")

# -------------------------------
# Evaluation
# -------------------------------
y_pred = model.predict(X_test_final)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# -------------------------------
# Save Files
# -------------------------------
pickle.dump(model, open("phishing_model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))
pickle.dump(scaler, open("scaler.pkl", "wb"))

print("✅ Hybrid v5 Model Saved Successfully")