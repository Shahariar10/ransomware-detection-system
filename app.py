import streamlit as st
import pandas as pd
import joblib

# ======================================
# Load Model
# ======================================

model = joblib.load("xgb_model.pkl")

features = joblib.load("feature_columns.pkl")

# ======================================
# App Title
# ======================================

st.title("Intelligent Ransomware Detection System")

st.write("Upload a CSV file to detect ransomware.")

# ======================================
# Upload CSV
# ======================================

uploaded_file = st.file_uploader(
    "Upload CSV File",
    type=["csv"]
)

# ======================================
# Prediction Section
# ======================================

if uploaded_file is not None:

    df = pd.read_csv(uploaded_file)

    st.subheader("Uploaded Dataset")

    st.write(df.head())

    # Preprocessing
    df = df.drop(
        ["FileName", "md5Hash"],
        axis=1,
        errors='ignore'
    )

    df = df.fillna(0)

    # Match feature order
    df = df[features]

    # Predict
    prediction = model.predict(df)

    # Result conversion
    result = []

    for p in prediction:

        if p == 0:
            result.append("⚠ Ransomware")

        else:
            result.append("✅ Benign")

    # Show results
    result_df = pd.DataFrame({
        "Prediction": result
    })

    st.subheader("Prediction Results")

    st.write(result_df)