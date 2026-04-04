"""
Advanced Phishing Detection & Awareness System
Model Training Script
Trains Random Forest + TF-IDF NLP models for phishing detection
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import os

print("\n" + "="*50)
print("  PHISHGUARD - MODEL TRAINING")
print("="*50)
print("\n[*] Training phishing detection models...\n")

# ─────────────────────────────────────────────
# 1. URL FEATURES MODEL
# ─────────────────────────────────────────────
print("[*] Training URL Detection Model...")

url_features = np.array([
    # PHISHING URLs (label=1)
    [52, 0, 1, 0, 3, 0.15, 3, 1, 0, 4],
    [68, 0, 0, 1, 0, 0.20, 1, 0, 0, 5],
    [45, 0, 1, 0, 4, 0.18, 2, 1, 0, 3],
    [34, 0, 0, 0, 0, 0.05, 1, 0, 1, 2],
    [89, 0, 0, 0, 6, 0.25, 4, 1, 0, 6],
    [55, 0, 1, 0, 2, 0.12, 3, 0, 0, 4],
    [42, 0, 0, 1, 0, 0.30, 1, 0, 0, 3],
    [76, 0, 0, 0, 5, 0.22, 5, 1, 0, 5],
    [28, 0, 0, 0, 0, 0.04, 1, 0, 1, 1],
    [61, 0, 1, 0, 3, 0.16, 2, 1, 0, 4],
    [48, 0, 0, 0, 7, 0.28, 3, 1, 0, 5],
    [93, 0, 1, 0, 4, 0.19, 4, 1, 0, 7],
    [37, 0, 0, 1, 0, 0.08, 1, 0, 0, 2],
    [72, 0, 0, 0, 5, 0.24, 3, 1, 0, 4],
    [58, 0, 1, 0, 2, 0.14, 2, 0, 1, 3],
    # SAFE URLs (label=0)
    [18, 1, 0, 0, 0, 0.00, 1, 0, 0, 1],
    [22, 1, 0, 0, 0, 0.00, 1, 0, 0, 2],
    [25, 1, 0, 0, 0, 0.02, 1, 0, 0, 2],
    [30, 1, 0, 0, 1, 0.03, 2, 0, 0, 3],
    [19, 1, 0, 0, 0, 0.00, 1, 0, 0, 1],
    [35, 1, 0, 0, 0, 0.02, 1, 0, 0, 3],
    [28, 1, 0, 0, 1, 0.01, 2, 0, 0, 2],
    [21, 1, 0, 0, 0, 0.00, 1, 0, 0, 1],
    [33, 1, 0, 0, 0, 0.03, 1, 0, 0, 3],
    [26, 1, 0, 0, 0, 0.01, 1, 0, 0, 2],
    [40, 1, 0, 0, 1, 0.04, 2, 0, 0, 3],
    [29, 1, 0, 0, 0, 0.02, 1, 0, 0, 2],
    [23, 1, 0, 0, 0, 0.00, 1, 0, 0, 1],
    [36, 1, 0, 0, 0, 0.03, 2, 0, 0, 2],
    [27, 1, 0, 0, 0, 0.01, 1, 0, 0, 2],
])

url_labels = np.array([1]*15 + [0]*15)

X_train_url, X_test_url, y_train_url, y_test_url = train_test_split(
    url_features, url_labels, test_size=0.2, random_state=42, stratify=url_labels
)

url_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
url_model.fit(X_train_url, y_train_url)

y_pred_url = url_model.predict(X_test_url)
url_accuracy = accuracy_score(y_test_url, y_pred_url)
url_precision = precision_score(y_test_url, y_pred_url, zero_division=0)
url_recall = recall_score(y_test_url, y_pred_url, zero_division=0)
url_f1 = f1_score(y_test_url, y_pred_url, zero_division=0)

print(f"  [*] Trained on {len(X_train_url)} samples, tested on {len(X_test_url)} samples")
print(f"  Accuracy:  {url_accuracy:.2%}")
print(f"  Precision: {url_precision:.2%}")
print(f"  Recall:    {url_recall:.2%}")
print(f"  F1-Score:  {url_f1:.2%}")

# ─────────────────────────────────────────────
# 2. TEXT PHISHING MODEL (Email + Social Media)
# ─────────────────────────────────────────────
print("\n[*] Training Text/NLP Detection Model...")

phishing_texts = [
    # Email phishing
    "URGENT your account has been suspended verify now click here immediately",
    "Your bank account will be closed unless you confirm your details immediately",
    "Congratulations you have won a prize claim your reward click the link",
    "Security alert your password has been compromised reset now urgent",
    "Dear customer your account shows suspicious activity verify your identity",
    "Final warning your account will be deleted in 24 hours act now",
    "You have been selected click here to claim your free gift limited time",
    "Your credit card has been charged unusually verify your account now",
    "Important notice your email storage is full upgrade immediately",
    "Your Apple ID has been locked click here to unlock your account",
    "PayPal account limited please verify your information immediately",
    "IRS tax refund available claim your money now limited time offer",
    "Your Netflix subscription is expiring update payment details now",
    "Microsoft account security alert verify your identity immediately",
    "Amazon order cancelled due to payment issue update billing info now",
    "Congratulations you are our lucky winner iPhone 15 click to claim now",
    "Send this message to 10 friends and receive 500 dollars instantly",
    "Earn money from home no experience needed click now",
    "Your account has been hacked change password immediately click this link",
    "Free gift card available for the next 100 users only click to claim",
    "Earn 1000 dollars daily working from home simple easy money guaranteed",
    "You have been randomly selected for a cash prize verify identity to claim",
    "Limited offer buy one get ten free hurry expires in one hour only",
    # SAFE texts
    "Hi John your meeting is scheduled for Tuesday at 3pm see you then",
    "Your order has been shipped and will arrive by Thursday tracking number provided",
    "Thank you for your purchase your receipt is attached for your records",
    "Reminder your dentist appointment is tomorrow at 10am please confirm",
    "The project files have been shared with you via Google Drive",
    "Happy birthday hope you have a wonderful day",
    "Your monthly statement is now available log in to your account to view",
    "The team meeting has been rescheduled to 2pm tomorrow please update your calendar",
    "Thanks for reaching out we will get back to you within 24 hours",
    "Your password was successfully changed if you did not make this change contact us",
    "Your package has been delivered to your front door",
    "The document you requested has been approved and sent for signature",
]

phishing_text_labels = [1]*23 + [0]*12

X_train_text, X_test_text, y_train_text, y_test_text = train_test_split(
    phishing_texts, phishing_text_labels, test_size=0.2, random_state=42, stratify=phishing_text_labels
)

text_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=500, ngram_range=(1, 2), stop_words='english', min_df=1)),
    ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
])

text_pipeline.fit(X_train_text, y_train_text)

y_pred_text = text_pipeline.predict(X_test_text)
text_accuracy = accuracy_score(y_test_text, y_pred_text)
text_precision = precision_score(y_test_text, y_pred_text, zero_division=0)
text_recall = recall_score(y_test_text, y_pred_text, zero_division=0)
text_f1 = f1_score(y_test_text, y_pred_text, zero_division=0)

print(f"  [*] Trained on {len(X_train_text)} samples, tested on {len(X_test_text)} samples")
print(f"  Accuracy:  {text_accuracy:.2%}")
print(f"  Precision: {text_precision:.2%}")
print(f"  Recall:    {text_recall:.2%}")
print(f"  F1-Score:  {text_f1:.2%}")

# ─────────────────────────────────────────────
# 3. SAVE MODELS
# ─────────────────────────────────────────────
print("\n[*] Saving models...")

models_dir = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(models_dir, exist_ok=True)

with open(os.path.join(models_dir, 'url_model.pkl'), 'wb') as f:
    pickle.dump(url_model, f)

with open(os.path.join(models_dir, 'text_model.pkl'), 'wb') as f:
    pickle.dump(text_pipeline, f)

print(f"  [*] Models saved to models/")
print("     - url_model.pkl  -> URL phishing detection")
print("     - text_model.pkl -> Email & social media detection")

print("\n" + "="*50)
print("  [*] TRAINING COMPLETE!")
print("="*50 + "\n")
print("[*] Start the server with: python app.py")
print("[*] Or deploy to Vercel/Render\n")
