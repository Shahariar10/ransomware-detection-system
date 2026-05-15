import streamlit as st
import pandas as pd
import pefile
import joblib
import tempfile

# ======================================
# LOAD MODEL
# ======================================

model = joblib.load("xgb_model.pkl")
features = joblib.load("feature_columns.pkl")

# ======================================
# PAGE CONFIG
# ======================================

st.set_page_config(
    page_title="Ransomware Detection System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Intelligent Ransomware Detection System")

st.write(
    "Upload CSV datasets or executable files (.exe, .dll, .scr)"
)

# ======================================
# FEATURE EXTRACTION FUNCTION
# ======================================

def extract_features(file_path):

    pe = pefile.PE(file_path)

    data = {}

    try:

        data["Machine"] = pe.FILE_HEADER.Machine
        data["SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
        data["Characteristics"] = pe.FILE_HEADER.Characteristics

        data["MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        data["MinorLinkerVersion"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        data["SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
        data["SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        data["AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        data["BaseOfCode"] = pe.OPTIONAL_HEADER.BaseOfCode
        data["ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
        data["SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment
        data["FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment
        data["MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        data["MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        data["MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        data["MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        data["SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
        data["Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        data["DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        data["SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        data["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections

    except:
        pass

    return data

# ======================================
# FILE UPLOADER
# ======================================

uploaded_files = st.file_uploader(
    "Upload Files",
    type=["csv", "exe", "dll", "scr"],
    accept_multiple_files=True
)

# ======================================
# PROCESS FILES
# ======================================

if uploaded_files:

    results = []

    for uploaded_file in uploaded_files:

        file_name = uploaded_file.name.lower()

        try:

            # ======================================
            # CSV FILE PROCESSING
            # ======================================

            if file_name.endswith(".csv"):

                df = pd.read_csv(uploaded_file)

                df = df.drop(
                    ["FileName", "md5Hash"],
                    axis=1,
                    errors="ignore"
                )

                df = df.fillna(0)

                for col in features:

                    if col not in df.columns:
                        df[col] = 0

                df = df[features]

                predictions = model.predict(df)

                probabilities = model.predict_proba(df)

                for i in range(len(df)):

                    pred = predictions[i]

                    if pred == 0:

                        label = "⚠️ Ransomware"

                        confidence = round(
                            probabilities[i][0] * 100,
                            2
                        )

                    else:

                        label = "✅ Benign"

                        confidence = round(
                            probabilities[i][1] * 100,
                            2
                        )

                    results.append({
                        "File": uploaded_file.name,
                        "Prediction": label,
                        "Confidence (%)": confidence
                    })

            # ======================================
            # EXE / DLL / SCR PROCESSING
            # ======================================

            else:

                with tempfile.NamedTemporaryFile(
                    delete=False
                ) as tmp:

                    tmp.write(uploaded_file.read())

                    temp_path = tmp.name

                feature_dict = extract_features(temp_path)

                df = pd.DataFrame([feature_dict])

                for col in features:

                    if col not in df.columns:
                        df[col] = 0

                df = df[features]

                pred = model.predict(df)[0]

                prob = model.predict_proba(df)[0]

                if pred == 0:

                    label = "⚠️ Ransomware"

                    confidence = round(prob[0] * 100, 2)

                else:

                    label = "✅ Benign"

                    confidence = round(prob[1] * 100, 2)

                results.append({
                    "File": uploaded_file.name,
                    "Prediction": label,
                    "Confidence (%)": confidence
                })

        except Exception as e:

            results.append({
                "File": uploaded_file.name,
                "Prediction": "❌ Error",
                "Confidence (%)": "-"
            })

    # ======================================
    # SHOW RESULTS
    # ======================================

    result_df = pd.DataFrame(results)

    st.subheader("🔍 Detection Results")

    st.dataframe(result_df)

    # ======================================
    # SUMMARY
    # ======================================

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