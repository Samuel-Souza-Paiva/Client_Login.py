import requests
import hashlib
import base64

# Configuração inicial
HOST = "http://HOST:PORT"
USERNAME = "system"
PASSWORD = ""
CLIENT_TYPE = "WINPC_V2"
PUBLIC_KEY = "<RSA_PUBLIC_KEY_BASE64>"  # Deve ser chave pública RSA codificada em Base64
MAC = "C8:D9:D2:16:AF:F6"

def md5_lower(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest().lower()

# 1. Primeiro passo - solicitar desafio
def request_challenge():
    url = f"{HOST}/brms/api/v1.0/accounts/authorize"
    payload = {
        "userName": USERNAME,
        "ipAddress": "",
        "clientType": CLIENT_TYPE
    }
    response = requests.post(url, json=payload)
    if response.status_code == 401:
        return response.json()
    raise Exception(f"Erro inesperado: {response.status_code} - {response.text}")

# 2. Segundo passo - autenticar com assinatura
def calculate_signature(password, userName, realm, randomKey):
    temp1 = md5_lower(password)
    temp2 = md5_lower(userName + temp1)
    temp3 = md5_lower(temp2)
    temp4 = md5_lower(userName + ":" + realm + ":" + temp3)
    signature = md5_lower(temp4 + ":" + randomKey)
    return signature, temp4

def send_auth(signature, randomKey):
    url = f"{HOST}/brms/api/v1.0/accounts/authorize"
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    payload = {
        "mac": MAC,
        "signature": signature,
        "userName": USERNAME,
        "randomKey": randomKey,
        "publicKey": PUBLIC_KEY,
        "encryptType": "MD5",
        "ipAddress": "",
        "clientType": CLIENT_TYPE,
        "userType": "0"
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        return response.json()
    raise Exception(f"Erro de autenticação: {response.status_code} - {response.text}")

# Execução do login
challenge = request_challenge()
realm = challenge["realm"]
randomKey = challenge["randomKey"]

signature, temp4 = calculate_signature(PASSWORD, USERNAME, realm, randomKey)
session_data = send_auth(signature, randomKey)

print("Token JWT:", session_data["token"])
print("Duration:", session_data["duration"])
print("TokenRate:", session_data["tokenRate"])
