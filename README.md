# ABE-for-Heath-Care-Data
Attribute Based Encryption for Protecting Healthcare Data

🚀 Features
Role-Based Access Control (RBAC): Users are categorized into roles (Doctor, Financial, Housekeeping, Blood Bank).
AES Encryption: Patient data is encrypted based on user roles.
RSA Key Management: Secure RSA encryption is used for key management.
Anomaly Detection: Uses an Isolation Forest model to detect unauthorized login attempts.
Custom Authentication: Ensures only authorized personnel access patient data.

#🛠 Role-Based Access Permissions
Role	Accessible Data
Doctor -	Name, Age, Gender, Blood Type, Medical Condition, Admission Date, Doctor, Hospital, Insurance, Billing, Room No., Admission Type, Discharge Date, Medication, Test Results
Financial -	Billing Amount, Insurance Provider
Housekeeping - Name, Room Number
Blood Bank - Name, Age, Blood Type, Hospital

#🔒 Security Mechanisms
AES-256 Encryption: Ensures patient data is stored securely.
RSA Encryption: Protects symmetric AES keys.
Anomaly Detection: Identifies unusual access patterns using Isolation Forest.
#📝 How it Works?
1️⃣ User logs in with credentials.
2️⃣ Authentication with risk assessment & anomaly detection.
3️⃣ Data encryption/decryption is role-specific.
4️⃣ Doctors can view patients with similar medical conditions.
5️⃣ Financial staff can access billing details.
6️⃣ Housekeeping can view room assignments.
7️⃣ Blood bank staff can check blood type availability.
