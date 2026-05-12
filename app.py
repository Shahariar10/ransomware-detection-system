import streamlit as st
import pandas as pd
import joblib

# =========================================
# PAGE CONFIG
# =========================================

st.set_page_config(
    page_title="Ransomware Detection System",
    page_icon="🛡️",
    layout="wide"
)

# =========================================
# LOAD MODEL & FEATURES
# =========================================

@st.cache_resource
def load_model():
    return joblib.load("xgb_model.pkl")

@st.cache_data
def load_features():
    return joblib.load("feature_columns.pkl")

model = load_model()
features = load_features()

# =========================================
# TITLE
# =========================================

st.title("🛡️ Intelligent Ransomware Detection System")

st.write(
    "Upload a CSV file to detect ransomware using the trained XGBoost model."
)

# =========================================
# FILE UPLOADER
# =========================================

uploaded_file = st.file_uploader(
    "Upload CSV File",
    type=["csv"]
)

# =========================================
# PREDICTION
# =========================================

if uploaded_file is not None:

    try:

        # Read CSV
        df = pd.read_csv(uploaded_file)

        st.subheader("📄 Uploaded Dataset")

        st.dataframe(df.head())

        # =========================================
        # PREPROCESSING
        # =========================================

        df = df.drop(
            ["FileName", "md5Hash"],
            axis=1,
            errors="ignore"
        )

        df = df.fillna(0)

        # Match training feature order
        missing_cols = [col for col in features if col not in df.columns]

        if len(missing_cols) > 0:

            st.error(
                f"Missing columns in uploaded CSV: {missing_cols}"
            )

        else:

            df = df[features]

            # =========================================
            # PREDICT
            # =========================================

            prediction = model.predict(df)

            # Probability
            try:
                probability = model.predict_proba(df)[:, 1]
            except:
                probability = None

            # =========================================
            # RESULT TABLE
            # =========================================

            results = []

            for i, pred in enumerate(prediction):

                if pred == 0:
                    label = "⚠️ Ransomware"
                else:
                    label = "✅ Benign"

                if probability is not None:
                    prob = round(float(probability[i]) * 100, 2)
                else:
                    prob = "N/A"

                results.append({
                    "Prediction": label,
                    "Confidence (%)": prob
                })

            result_df = pd.DataFrame(results)

            # =========================================
            # SHOW RESULTS
            # =========================================

            st.subheader("🔍 Prediction Results")

            st.dataframe(result_df)

            # =========================================
            # SUMMARY
            # =========================================

            ransomware_count = (
                result_df["Prediction"]
                .str.contains("Ransomware")
                .sum()
            )

            benign_count = (
                result_df["Prediction"]
                .str.contains("Benign")
                .sum()
            )

            st.subheader("📊 Summary")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Total Files",
                len(result_df)
            )

            col2.metric(
                "Ransomware Detected",
                ransomware_count
            )

            col3.metric(
                "Benign Files",
                benign_count
            )

            # =========================================
            # DOWNLOAD RESULTS
            # =========================================

            csv = result_df.to_csv(index=False)

            st.download_button(
                label="⬇️ Download Prediction Results",
                data=csv,
                file_name="prediction_results.csv",
                mime="text/csv"
            )

    except Exception as e:

        st.error(f"Error: {e}")