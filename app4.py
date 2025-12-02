import streamlit as st
import pandas as pd
import numpy as np
import joblib
import ipaddress
from tensorflow.keras.models import load_model
from sklearn.svm import SVC

# Load models and scaler
ann_model = load_model("ann_model.h5")
svm_model = joblib.load("svm_model.pkl")
scaler = joblib.load("scaler.pkl")
feature_names = joblib.load("ann_features.pkl")

st.title("***IPv6 DoS Attack Detection Tool***(SVM+ANN Ensemble)")
st.markdown("Upload a CSV log file to detect potential **ICMPv6 Flood** attacks using an ensemble of SVM and ANN models.")

uploaded_file = st.file_uploader("Upload your IPv6 log file", type=["csv"])

def preprocess_data(df):
    df = df.copy()
    df.drop_duplicates(inplace=True)

    def parse_timestamp(ts):
        try:
            if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace('.', '', 1).isdigit()):
                return float(ts)
            parsed = pd.to_datetime(ts, format='%m/%d-%H:%M:%S.%f', errors='coerce')
            return parsed.timestamp() if pd.notnull(parsed) else np.nan
        except:
            return np.nan

    df['Timestamp'] = df['Timestamp'].apply(parse_timestamp)
    df['Timestamp'] = df['Timestamp'] - df['Timestamp'].min()
    df['Timestamp'] = df['Timestamp'].fillna(df['Timestamp'].mean())

    if 'Length' in df.columns:
        df['Length'] = df['Length'].replace(0, df['Length'].median())
    else:
        df['Length'] = df['Length'].median()

    def ipv6_to_int(ip):
        try:
            return int(ipaddress.IPv6Address(ip))
        except:
            return 0

    df['Source_IPv6_int'] = df.get('Source_IPv6', '').apply(ipv6_to_int)
    df['Destination_IPv6_int'] = df.get('Destination_IPv6', '').apply(ipv6_to_int)

    df['is_ICMPv6_flood'] = df.get('Info', '').str.contains('ICMPv6 Flood Detected', case=False, na=False).astype(int)

    if 'Protocol' in df.columns:
        df = pd.get_dummies(df, columns=['Protocol'], prefix='Protocol', dummy_na=False)

    # Align columns with feature_names
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    df = df[[col for col in df.columns if col in feature_names]]

    df = df[feature_names]

    # Drop rows with NaNs
    df = df.dropna()

    return df

if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file)

        features = preprocess_data(raw_df)
        valid_indices = features.index
        features_scaled = scaler.transform(features)

        # Predict with SVM
        svm_prob = svm_model.predict_proba(features_scaled)[:, 1]
        svm_pred = (svm_prob > 0.5).astype(int)

        # Predict with ANN
        ann_prob = ann_model.predict(features_scaled).flatten()
        ann_pred = (ann_prob > 0.5).astype(int)

        # Combine predictions (weighted average)
        combined_prob = 0.5 * svm_prob + 0.5 * ann_prob
        combined_pred = (combined_prob > 0.5).astype(int)

        # Prepare results DataFrame
        results_df = raw_df.copy()
        results_df['Source_IPv6_int'] = features['Source_IPv6_int']
        results_df['SVM_Probability'] = 0.0
        results_df['ANN_Probability'] = 0.0
        results_df['Combined_Probability'] = 0.0
        results_df['Prediction'] = 0
        results_df['Result'] = 'Normal'

        # Update processed rows
        results_df.loc[valid_indices, 'SVM_Probability'] = svm_prob
        results_df.loc[valid_indices, 'ANN_Probability'] = ann_prob
        results_df.loc[valid_indices, 'Combined_Probability'] = combined_prob
        results_df.loc[valid_indices, 'Prediction'] = combined_pred
        results_df.loc[valid_indices, 'Result'] = results_df.loc[valid_indices, 'Prediction'].map({0: 'Normal', 1: 'ICMPv6 Flood'})

        st.success("Detection complete!")

        st.write("### Prediction Confidence")
        st.write(f"Average SVM attack probability: {results_df['SVM_Probability'].mean():.2%}")
        st.write(f"Average ANN attack probability: {results_df['ANN_Probability'].mean():.2%}")
        st.write(f"Average combined attack probability: {results_df['Combined_Probability'].mean():.2%}")

        st.write("### Prediction Results")
        st.dataframe(results_df[['Source_IPv6', 'Destination_IPv6', 'SVM_Probability', 'ANN_Probability', 'Combined_Probability', 'Result']].sort_values('Combined_Probability', ascending=False))

        st.write("### Attack Summary")
        st.bar_chart(results_df['Result'].value_counts())

    except Exception as e:
        st.error(f"Error processing file: {e}")