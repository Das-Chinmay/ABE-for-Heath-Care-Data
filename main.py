import csv
import secrets
import random
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ROLES_ATTRIBUTES_MAPPING = {
    "doctor": ["Name", "Age", "Gender", "Blood Type", "Medical Condition", "Date of Admission", "Doctor", "Hospital", "Insurance Provider", "Billing Amount", "Room Number", "Admission Type", "Discharge Date", "Medication", "Test Results"],
    "financial": ["Billing Amount", "Insurance Provider"],
    "housekeeping": ["Name", "Room Number"],
    "blood_bank": ["Name", "Age", "Blood Type", "Hospital"]
}

def load_dataset(file_path):
    dataset = []
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            dataset.append(row)
    return dataset
def extract_unique_values(dataset, column):
    unique_values = set()
    for row in dataset:
        unique_values.add(row[column])
    return list(unique_values)

medical_staff_credentials = None

financial_staff_credentials = {
    "accountant": "password",
    "analyst": "password"
}

housekeeping_staff_credentials = {
    "cleaner": "password"
}

blood_bank_staff_credentials = {
    "blood_bank_staff": "password"
}

def create_medical_staff_credentials(dataset):
    global medical_staff_credentials
    medical_staff_credentials = {}
    doctors = extract_unique_values(dataset, 'Doctor')
    for doctor in doctors:
        password = "password123"
        medical_staff_credentials[doctor] = password

def authenticate(username, password):
    risk_score = 0.3  # 
    if risk_score < 0.5:
        if medical_staff_credentials is not None and username in medical_staff_credentials and medical_staff_credentials[username] == password:
            medical_condition = None
            for row in dataset:  
                if row['Doctor'] == username:
                    medical_condition = row['Medical Condition']
                    break
            return True, "doctor", medical_condition
        elif username in financial_staff_credentials and financial_staff_credentials[username] == password:
            return True, "financial", None
        elif username in housekeeping_staff_credentials and housekeeping_staff_credentials[username] == password:
            return True, "housekeeping", None
        elif username in blood_bank_staff_credentials and blood_bank_staff_credentials[username] == password:
            return True, "blood_bank", None
    return False, None, None

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_with_rsa(public_key, data):
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_with_rsa(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

def encrypt_dataset(dataset, key):
    encrypted_dataset = []
    for row in dataset:
        encrypted_row = encrypt_row(row, key)
        encrypted_dataset.append(encrypted_row)
    return encrypted_dataset

def decrypt_dataset(encrypted_dataset, key, user_role):
    decrypted_dataset = []
    for row in encrypted_dataset:
        if user_role == "doctor":
            decrypted_row = decrypt_row(row, key, ROLES_ATTRIBUTES_MAPPING["doctor"])
        elif user_role == "financial":
            decrypted_row = decrypt_row(row, key, ROLES_ATTRIBUTES_MAPPING["financial"])
        elif user_role == "housekeeping":
            decrypted_row = decrypt_row(row, key, ROLES_ATTRIBUTES_MAPPING["housekeeping"])
        elif user_role == "blood_bank":
            decrypted_row = decrypt_row(row, key, ROLES_ATTRIBUTES_MAPPING["blood_bank"])
        else:
            decrypted_row = encrypt_row(row, key)
        decrypted_dataset.append(decrypted_row)
    return decrypted_dataset

def encrypt_row(row, key):
    encrypted_row = row.copy()
    for field, value in row.items():
        iv = secrets.token_bytes(16)  
        cipher = Cipher(algorithms.AES(key), mode=modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(value.encode()) + encryptor.finalize()
        encrypted_row[field] = iv.hex() + encrypted_message.hex() 
    return encrypted_row

def decrypt_row(row, key, attributes):
    decrypted_row = {}
    for attribute in attributes:
        iv = bytes.fromhex(row[attribute][:32])  
        encrypted_message = bytes.fromhex(row[attribute][32:])
        cipher = Cipher(algorithms.AES(key), mode=modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        decrypted_row[attribute] = decrypted_message.decode()
    return decrypted_row

def filter_dataset(dataset, role, username):
    if role == "doctor":
        return [row for row in dataset if row["Doctor"] == username]
    elif role == "financial":
        return dataset 
    elif role == "housekeeping":
        return dataset  
    elif role == "blood_bank":
        return dataset 
    else:
        return dataset  

input_file = "test_dataset.csv"
dataset = load_dataset(input_file)

create_medical_staff_credentials(dataset)

key = secrets.token_bytes(16)  
encrypted_dataset = encrypt_dataset(dataset, key)

print("Encrypted Dataset:")
for row in encrypted_dataset:
    print(row)
    
def load_access_pattern_data(file_path):
    data = pd.read_csv(file_path, parse_dates=['Timestamp'])
    return data
def load_authentication_data(file_path):
    data = pd.read_csv(file_path, parse_dates=['Timestamp'])
    return data

access_pattern_data = load_access_pattern_data("access_pattern_data.csv")
authentication_data = load_authentication_data("authentication_data.csv")
 
access_features = ['Timestamp']
access_X = pd.DataFrame(access_pattern_data)[access_features]

access_scaler = StandardScaler()
access_X_scaled = access_scaler.fit_transform(access_X)

access_model = IsolationForest(contamination=0.1)
access_model.fit(access_X_scaled)

def authenticate_with_anomaly_detection(username, password):
    authenticated, staff_type, medical_condition = authenticate(username, password)

    if authenticated:
        user_data = authentication_data[authentication_data['Username'] == username][['Timestamp']]
        if not user_data.empty:
            user_data_scaled = access_scaler.transform(user_data)
            is_anomaly = access_model.predict(user_data_scaled)

            if -1 in is_anomaly:
                print("Warning: Anomaly detected in user access pattern during authentication!")
               
    return authenticated, staff_type, medical_condition

while True:
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    authenticated, staff_type, medical_condition = authenticate_with_anomaly_detection(username, password)
    if authenticated:
        print("Authentication successful!")
        if medical_condition:  
            filtered_dataset = [row for row in dataset if row["Medical Condition"] == medical_condition]
            print("\nPatients suffering from the same medical condition:")
            for row in filtered_dataset:
                print(row)
        elif staff_type == "financial":
            hospital_name = input("Enter the hospital name: ")
            print("\nBilling Amount, Insurance Provider, and Patient Names for Hospital:", hospital_name)
            for row in dataset:
                if row["Hospital"] == hospital_name:
                    print("Billing Amount:", row["Billing Amount"])
                    print("Insurance Provider:", row["Insurance Provider"])
                    print("Patient Name:", row["Name"])
        elif staff_type == "housekeeping":
            hospital_name = input("Enter the hospital name: ")
            print("\nPatient Name and Room Number for Hospital:", hospital_name)
            for row in dataset:
                if row["Hospital"] == hospital_name:
                    print("Patient Name:", row["Name"])
                    print("Room Number:", row["Room Number"])
        elif staff_type == "blood_bank":
            print("\nName, Age, Blood Type, and Hospital Name for Patients:")
            for row in dataset:
                print("Name:", row["Name"])
                print("Age:", row["Age"])
                print("Blood Type:", row["Blood Type"])
                print("Hospital:", row["Hospital"])
        else:
            print("Welcome,", staff_type.title(), "staff!")
        break  
    else:
        print("Authentication failed! Please try again.")
