# Final-Year-Project-2
Final Year Project SVM + ANN / 
Flavian Navin Wenceslas /
# 📘 Theoretical Background

This project focuses on detecting DoS (Denial of Service) attacks in IPv6 networks using a hybrid approach that combines Snort, Support Vector Machine (SVM), and Artificial Neural Network (ANN). It also highlights the role of Jupyter Lab as the development environment for machine learning experiments and result visualization.

The increasing shift toward IPv6 brings stronger addressing capabilities but also introduces complexities in detecting DoS attacks due to its expanded header structure and diverse extension headers. Traditional IDS tools such as Snort may struggle to detect new or evolving attack patterns—highlighting the need for more adaptive techniques like machine learning.

This theoretical framework introduces key concepts, tools, and techniques used to develop a more versatile detection mechanism for securing IPv6 networks against dynamic DoS attacks.

🔍 3.1 Snort – Signature-Based Intrusion Detection System (IDS)

Snort is a widely used, signature-based IDS capable of performing packet logging and real-time network traffic analysis. It compares traffic against known attack signatures to detect malicious activity such as DoS attacks.

In this project, Snort plays two main roles:

Traffic Capture & Logging
Snort monitors IPv6 traffic in real time and generates logs containing packet information and alerts.

Baseline Detection Mechanism
Snort's signature-based detection is used as the benchmark for evaluating whether machine learning models (SVM/ANN) can achieve better detection accuracy, particularly for attacks that do not match existing signatures.

This helps assess whether machine learning can enhance detection rates and overcome the limitations of static rule-based systems.

🤖 3.2 Support Vector Machine (SVM)

Support Vector Machine (SVM) is a supervised machine learning algorithm well-suited for classification tasks. It separates classes by finding the optimal hyperplane in the feature space.

In this project:

CPU usage and memory usage are used as features.

Features are extracted from Snort logs.

The SVM model learns patterns associated with DoS attacks versus normal traffic.

Why SVM?

It helps detect unknown or modified attack patterns.

It reduces false positives and false negatives more effectively than signature-based detection.

It complements Snort, improving overall intrusion detection capability.

SVM serves as the primary ML method used to enhance detection of IPv6-specific DoS attacks.

🧠 3.3 Artificial Neural Network (ANN)

Artificial Neural Network (ANN) is another supervised learning technique inspired by the human brain, ideal for complex pattern recognition tasks.

In this project, ANN is used to:

Classify network traffic as normal or DoS attack.

Analyze CPU and memory consumption patterns derived from Snort logs.

Detect both known and unknown attack behaviours.

Advantages of ANN:

Learns deeply from training data.

Recognizes sophisticated and adaptive DoS attacks.

Further reduces misclassifications compared to traditional IDS tools.

ANN acts as an additional intelligent detection layer, improving the robustness of IPv6 intrusion detection.

🧪 3.4 Jupyter Lab – Development Environment

Jupyter Lab is used extensively throughout this project due to its:

Interactive coding workflow

Strong support for Python and ML libraries (pandas, scikit-learn, matplotlib)

Excellent visualisation capabilities

Jupyter Lab enables:

Snort log processing

SVM and ANN model development

Immediate feedback through visual outputs (accuracy graphs, confusion matrices)

Rapid experimentation and model tuning

It forms the core environment for data analysis and machine learning implementation.

🧼 3.5 Data Preprocessing

Data preprocessing is a critical step to ensure accurate machine learning performance.
Although Snort logs provide valuable raw traffic data, they include fields such as:

Packet sizes

Protocol types

Timestamps

Metadata for inbound/outbound packets

Before training ML models, these logs need to be:

Cleaned

Transformed

Feature-extracted

Normalized

Using pandas and scikit-learn, raw Snort logs are converted into a structured dataset suitable for SVM and ANN training. Proper preprocessing significantly enhances the accuracy of DoS detection.
