# -*- coding: utf-8 -*-
"""
Script to Azure IPs from Microsoft and add to Snowflake Network Policy

@author: sgsshankar, www.shankarnarayanan.com
@license: Apache License, Version 2.0
@copyright (c) Shankar Narayanan SGS
"""
import snowflake.connector
import requests
import hashlib
import json
import os
import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization


configfile = "config.json"

# read the config file
configfile = "config.json"
with open(configfile) as json_data_file:
    data = json.load(json_data_file)

# navigate the microsoft url to locate the json file
try:
    download_url = data["whitelist"]["url"]
    req = requests.get(download_url)
    if req.status_code == 200:
        download_page = req.text
    else:
        print("Response not received")
except Exception as e:
    print(e)
    raise Exception(e)

# simulate button click on download page to get the download link
try:
    soup = BeautifulSoup(download_page, 'html.parser')
    download_element = soup.find(lambda tag:tag.name=="strong" and "click here to download manually" in tag.text)
    parent_element = download_element.parent
    if parent_element.name == 'a' and 'https://download.microsoft.com' in parent_element['href']:
        msurl = parent_element['href']
except Exception as e:
    print(e)
    print("Error Happened")

print(msurl)

# import the json file containing the ips from microsoft website
resp = requests.get(msurl)
txt = resp.json()
ip=[]
for x in txt['values']:
    if x['id'] in data["whitelist"]["keys"]:
       ip.append(x['properties']['addressPrefixes'])

# take a checksum of the file to store and compare everytime the script is executed to find if new ips have been added. 
txt_md5 = hashlib.md5(json.dumps(txt, sort_keys=True).encode('utf-8')).hexdigest()

policy = data["whitelist"]["policy"]
pkey = data["snowflake"]["pkey"]

# read private key for authentication
with open(pkey, "rb") as key:
    p_key= serialization.load_pem_private_key(
        key.read(),
        password=os.environ['PRIVATE_KEY_PASSPHRASE'].encode(),
        backend=default_backend()
    )

pkb = p_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())

# connect to snowflake account
con = snowflake.connector.connect(
    user=data["snowflake"]["user"],         
    private_key=pkb,
    account=data["snowflake"]["account"],
    warehouse=data["snowflake"]["warehouse"],
    database=data["snowflake"]["database"],
    schema=data["snowflake"]["schema"],
    role=data["snowflake"]["role"],
    session_parameters={
        'QUERY_TAG': 'NetworkPolicyUpdate',
    }
)

cursor = con.cursor()

try:
  sql = 'alter warehouse {} resume;'.format(data["snowflake"]["warehouse"])
  cursor.execute(sql)
except:
    pass

sql = "Select * from aad_ip_checksum;"
rset = cursor.execute(sql)
df=cursor.fetch_pandas_all()

if df.empty:
    ipstr = ','.join(str(v) for v in ip).replace("[","").replace("]","").rstrip(":")
    ip_list = ipstr.split(",")
    ip_list =[ x for x in ip_list if ":" not in x ]
    ips=""
    for c in ip_list:
        ips=ips + c + ','  
    ips=ips[:-1]    
    sql="CREATE OR REPLACE NETWORK POLICY "+policy+" ALLOWED_IP_LIST = (" + ips + ")"
    cursor.execute (sql)
    #storing checksum in db
    sql = "insert into aad_ip_checksum values(GETDATE(),"+ "'"+txt_md5+"'" +")"
    cursor.execute (sql)
   
else:
    # compare checksum of newly downloaded ip file with the file containing last added ips
    prev_cksum=df.loc[0,'CHECKSUM']
    if(prev_cksum==txt_md5):
        print("No new changes in ip list")
    else:
        # delete old checksum and add  checksum of latest file
        sql = "truncate aad_ip_checksum"
        cursor.execute (sql)
        add_policy()