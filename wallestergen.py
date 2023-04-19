import csv
import time, requests, base64
from jose import jws
from cryptography.hazmat.primitives import serialization
import os, base64
from age.keys.rsa import RSAPrivateKey, RSAPublicKey
from age.primitives.rsa_oaep import rsa_decrypt, rsa_encrypt
import yaml
import base64
current_dir = os.path.dirname(__file__)
config_path = os.path.join(current_dir, "config.yml")
config = yaml.safe_load(open(config_path))

def get_public_key_base64():
    with open(config['public_key_path']) as key_file:
        message = key_file.read()
        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')

    return base64_message


def get_private_key_raw():
    with open(config['private_key_path'], 'rb') as key_file:
        message = key_file.read()

    return message


## Need api key within this function, private key must be same as the one used to assign to api key
def generateJWT():
    apiKey = config['api_key']
    private_key_path = config['private_key_path']
    payload = {"api_key": apiKey, "ts": int(time.time())}
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    key = private_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    signed = "Bearer " + str(jws.sign(payload, key, algorithm='RS256'))
    return signed
    
def get_card_number(card_id):
    getEncrypted = False
    
    while getEncrypted == False:
        url = f"https://api-frontend.wallester.com/v1/cards/{card_id}/encrypted-card-number"
        headers = {
                "Authorization": generateJWT()
            }

        payload = {
                "public_key": get_public_key_base64()
            }
        try:
            data = requests.post(url, headers=headers, json=payload).json()
            encryptedCard = data["encrypted_card_number"]
            encrypted = encryptedCard.replace("\n", "").replace("-----BEGIN CardNumber MESSAGE-----", "").replace("-----END CardNumber MESSAGE-----", "")
            getEncrypted = True
        except Exception as e:
            print(data)
            print(e)
            continue

    label = b"CardNumber"
    encrypted = bytes(encrypted, encoding='iso-8859-1')
    base64_bytes = base64.b64decode(encrypted)
    base64_message = base64_bytes.decode('iso-8859-1')
    base64_message = bytes(base64_message, encoding='iso-8859-1')
    private_key = RSAPrivateKey.from_pem(get_private_key_raw())

    decrypted = str(rsa_decrypt(private_key, label, base64_message)).replace("b'", "").replace("'", "")
    return decrypted


## public/private key required here
def get_card_cvv(card_id):
    getEncrypted = False
    while getEncrypted == False:
        url = f"https://api-frontend.wallester.com/v1/cards/{card_id}/encrypted-cvv2"
        headers = {
                "Authorization": generateJWT()
            }

        payload = {
                "public_key": get_public_key_base64()
            }
        try:
            data = requests.post(url, headers=headers, json=payload).json()
            encryptedCard = data["encrypted_cvv2"]
            encrypted = encryptedCard.replace("\n", "").replace("-----BEGIN CVV2 MESSAGE-----", "").replace("-----END CVV2 MESSAGE-----", "")
            getEncrypted = True
        except Exception as e:
            print(data)
            print(e)
            continue

    label = b"CVV2"
    encrypted = bytes(encrypted, encoding='iso-8859-1')
    base64_bytes = base64.b64decode(encrypted)
    base64_message = base64_bytes.decode('iso-8859-1')
    base64_message = bytes(base64_message, encoding='iso-8859-1')

    private_key = RSAPrivateKey.from_pem(get_private_key_raw())

    decrypted = str(rsa_decrypt(private_key, label, base64_message)).replace("b'", "").replace("'", "")
    return decrypted

def get_all_active_cards():
    getEncrypted = False
    while getEncrypted == False:
        url = "https://api-frontend.wallester.com/v1/product-cards?from_record=0&records_count=1000&is_active=true"
        headers = {
                "Authorization": generateJWT()
            }
        try:
            data = requests.get(url, headers=headers).json()
            return data
        except Exception as e:
            print(e)
            print(data)
            continue

## Account id key required here
def create_card(name):
    try:
        url = "https://api-frontend.wallester.com/v1/cards"

        headers = {
            "Authorization": generateJWT()
        }

        payload = {
        "account_id": config['account_id'],
        "type": "Virtual",
        "name": name,
        "3d_secure_settings": {
            "type": "SMSOTPAndStaticPassword",
            "mobile": "+4591489911",
            "password": "12345678",
        }
        }

        data = requests.post(url, headers=headers, json=payload).json()
        add_or_update_local_csv(data['card'])
        
    except Exception as e:
        print(e)

def get_merchant_rule(card_id):
    try:
        url = "https://api-frontend.wallester.com/v1/cards/"+card_id+"/merchant-rules"

        headers = {
            # "X-Product-Code": "TODO",
            # "X-Audit-Source": "TODO",
            # "X-Audit-User-Id": "TODO",
            "Authorization": generateJWT()
        }

        response = requests.get(url, headers=headers).json()
        print(response)
        
    except Exception as e:
        print(e)

def add_merchant_rule(card_id):
    try:
        url = "https://api-frontend.wallester.com/v1/cards/"+card_id+"/merchant-rules"

        headers = {
            # "X-Product-Code": "TODO",
            # "X-Audit-Source": "TODO",
            # "X-Audit-User-Id": "TODO",
            "Authorization": generateJWT()
        }

        payload = {
            "type":"MerchantCategoryCode",
            "value": "5661",
            "is_whitelist":True
        }

        data = requests.post(url, headers=headers, json=payload).json()
        print(data)
        
    except Exception as e:
        print(e)

def update_card_name(card_id, new_name):
    try:
        url = "https://api-frontend.wallester.com/v1/cards/"+card_id+"/name"

        headers = {
            "Authorization": generateJWT()
        }

        payload = {
            "name":new_name
        }

        response = requests.patch(url, headers=headers, json=payload).json()
        return response
        
    except Exception as e:
        print(e)

def update_3DS_settings(card_id, phone):
    try:
        url = "https://api-frontend.wallester.com/v1/cards/"+card_id+"/3d-secure/settings"

        headers = {
            "Authorization": generateJWT()
        }

        payload = {
            "type":"SMSOTPAndStaticPassword",
            "language_code":"ENG",
            "mobile":phone,
            "password":"12345678"
        }

        response = requests.patch(url, headers=headers, json=payload).json()
        return response
        
    except Exception as e:
        print(e)



def write_line_to_file(filename, columns):
    with open(os.path.join(current_dir, filename+".csv"), 'a+', newline='\n', encoding='utf-8') as new_file:
        csvwriter = csv.writer(new_file) # 2. create a csvwriter object
        csvwriter.writerow(columns) # 5. write the rest of the data
    
def write_lines_to_file_replaces(filename, columns_and_rows):
    with open(os.path.join(current_dir, filename+".csv"), 'w', newline='\n', encoding='utf-8') as new_file:
        csvwriter = csv.writer(new_file) # 2. create a csvwriter object
        csvwriter.writerows(columns_and_rows) # 5. write the rest of the data

def get_all_csv_lines(filename):
    with open(os.path.join(current_dir, filename+".csv"), 'r') as read_obj:
        csv_reader = csv.reader(read_obj)
        list_of_csv = list(csv_reader)
        return list_of_csv


def add_or_update_local_csv(card):
    #DO WE HAVE A MATCH IN LOCAL FILE?
    local_card_ids = get_all_card_ids_from_csv()
    if card['id'] in local_card_ids: #UPDATE
        
        #find local card details
        local_cards = get_all_csv_lines('cards')
        card_match = next(c for c in local_cards if c[0] == card['id'])
        
        if "*" in card_match[3]: #update card_number
            card_number = get_card_number(card['id'])
            replace_card_csv_value(card['id'], 3, card_number)
        
        if "*" in card_match[5]: #update cvv
            card_cvv = get_card_cvv(card['id'])
            replace_card_csv_value(card['id'], 5, card_cvv)

        #UPDATE NAME
        if 'name' in card:
            replace_card_csv_value(card['id'], 1, card['name'])

        #UPDATE PHONE NUMBER
        replace_card_csv_value(card['id'], 2, card['3d_secure_settings']['mobile'])
        
    else: #ADD
        card['masked_card_number'] = get_card_number(card['id'])
        card_cvv = get_card_cvv(card['id'])
        add_card_to_csv(card, card_cvv)

    
    


def replace_card_csv_value(card_id, column_index, new_value):
    all_rows = get_all_csv_lines('cards')
    for row in all_rows:
        if row[0] == card_id:
            row[column_index] = new_value
            break
    
    write_lines_to_file_replaces('cards', all_rows)

def get_all_card_ids_from_csv():
    all_rows = get_all_csv_lines('cards')
    return [card[0] for card in all_rows]

def add_card_to_csv(card, _cvv="***"):
    card_id = card['id']
    name = card['name'] if 'name' in card else 'none'  
    exp = card['expiry_date'].replace('-31T23:59:59Z','').replace('-30T23:59:59Z','')
    mobile = card['3d_secure_settings']['mobile']
    card_number = card['masked_card_number']
    cvv = _cvv
    write_line_to_file("cards", [card_id, name, mobile, card_number, exp, cvv])


### add all active cards to file with their IDS ###
# def add_all_active_cards_to_csv():
#     cards = get_all_active_cards()
#     for card in cards['cards']:
#         add_card_to_csv(card)


# card_ids_from_csv = get_all_card_ids_from_csv()
# for card_id in card_ids_from_csv:
#     card_number = get_card_number(card_id)
#     card_cvv = get_card_cvv(card_id)

#     replace_card_csv_value(card_id, 3, card_number)
#     replace_card_csv_value(card_id, 5, card_cvv)

### GENERATE CARDS ###
for n in range(900,3000):
    card_name = "JW"+str(n)
    print("creating card " + card_name)
    create_card(card_name)

#response = update_card_name("00c8ea05-ee57-4ce2-b652-c113096ac9eb", "lort")

# all_local_cards = get_all_card_ids_from_csv()
# for index, card in enumerate(all_local_cards):
#     print("idx: " + str(index))
#     response = update_3DS_settings(card, "+4591489911")
#     #response = update_card_name(card, "JW"+str(index)) #update_3DS_settings(card, "+4591489911")
#     add_or_update_local_csv(response['card'])

# i = 0
# while i < 267:
#     create_card()
#     i = i + 1