import email
from email.parser import HeaderParser
from email import message_from_file,policy
import sys
import hashlib
import re
import os
import json
import quopri
from datetime import datetime
import pandas as pd


# Reading the EML file 
filename = "C:\\phish_alert.eml"
file_format = filename.split('.')[-1]
print("file format is ", file_format)
with open(filename,"r",encoding="utf-8") as file:
    data = file.read().rstrip()
#Extracting the header   
headers = HeaderParser().parsestr(data, headersonly=True)



# Creating JSON format file to hold header data
data = json.loads('{"Headers":{"Data":{}}}')
    # Put Header data to JSON
for i,v in headers.items():
    data["Headers"]["Data"][i.lower()] = v.replace('\t', '').replace('\n', '')


# checking type
type(data["Headers"]["Data"])

# Printing dictionary keys
data["Headers"]["Data"].keys()


# saving dictionary and values to DataFrame
df = pd.DataFrame(data=data["Headers"]["Data"].items(), columns=["Key", "Value"])


# Extracting few more values and creating new rows
# Extract IP addresses from "received" key
ip_addresses = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", df.loc[df['Key'] == 'received', 'Value'].values[0])

# Create a new DataFrame for the additional row
new_row = pd.DataFrame({'Key': ['received_IP addresses'], 'Value': [ip_addresses]})

# Concatenate the original DataFrame with the new row
df = pd.concat([df, new_row], ignore_index=True)


# Extract SPF status
spf_status = re.findall(r"spf=([^\s;]+)", df.loc[df['Key'] == 'authentication-results', 'Value'].values[0])

# Extract DKIM status
dkim_status = re.findall(r"dkim=([^\s;]+)", df.loc[df['Key'] == 'authentication-results', 'Value'].values[0])

# Extract DMARC status
dmarc_status = re.findall(r"dmarc=([^\s;]+)", df.loc[df['Key'] == 'authentication-results', 'Value'].values[0])

# Extract authentication IP addresses
ip_addresses = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", df.loc[df['Key'] == 'authentication-results', 'Value'].values[0])

# Create new DataFrames for the additional rows
spf_row = pd.DataFrame({'Key': ['SPF_Status'], 'Value': [spf_status]})
dkim_row = pd.DataFrame({'Key': ['DKIM_Status'], 'Value': [dkim_status]})
dmarc_row = pd.DataFrame({'Key': ['DMARC_Status'], 'Value': [dmarc_status]})
ip_row = pd.DataFrame({'Key': ['authentication_IP_Addresses'], 'Value': [ip_addresses]})

# Concatenate the original DataFrame with the new rows
df = pd.concat([df, spf_row, dkim_row, dmarc_row, ip_row], ignore_index=True)

print(df)

# References: https[:]//github[.]com/keraattin/EmailAnalyzer/blob/main/email-analyzer[.]py
# I copied the file reading and file type detection module from above referenced code
