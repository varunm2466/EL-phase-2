# main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
from difflib import SequenceMatcher

# -----------------------------------
# FastAPI App
# -----------------------------------
app = FastAPI(title="Prompt Injection Detector")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------
# Load CSV Dataset
# Keep malicious_prompts_500.csv in same folder
# -----------------------------------
df = pd.read_csv("malicious_prompts_500.csv")

# -----------------------------------
# Input Schema
# -----------------------------------
class PromptInput(BaseModel):
    text: str

# -----------------------------------
# Similarity Function
# -----------------------------------
def similarity(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

# -----------------------------------
# Detection Logic
# -----------------------------------
def detect_prompt(user_text):
    best_score = 0
    best_prompt = ""
    best_category = ""

    for _, row in df.iterrows():
        score = similarity(user_text, row["prompt"])

        if score > best_score:
            best_score = score
            best_prompt = row["prompt"]
            best_category = row["category"]

    confidence = round(best_score * 100, 2)

    if best_score >= 0.75:
        label = "Malicious Prompt Detected"
        level = "High"
    elif best_score >= 0.45:
        label = "Suspicious Prompt"
        level = "Medium"
    else:
        label = "Safe Prompt"
        level = "Low"

    return {
        "response": label,
        "threat_level": level,
        "confidence": confidence,
        "matched_prompt": best_prompt,
        "category": best_category
    }

# -----------------------------------
# Routes
# -----------------------------------
@app.get("/")
def home():
    return {
        "message": "Prompt Injection Detector Backend Running"
    }

@app.post("/predict")
def predict(data: PromptInput):
    result = detect_prompt(data.text)

    return {
        "input": data.text,
        **result
    }