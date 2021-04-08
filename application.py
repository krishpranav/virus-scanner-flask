#!/usr/bin/env/python

#imports
import os
import numpy as np
import pandas as pd
import requests
import time

from flask import Flask, flash, redirect, url_for, request, render_template
from werkzeug.utils import secure_filename

application = Flask(__name__)

UPLOAD_FOLDER = 'upload/'

URL = 'https://www.virustotal.com/vtapi/v2/file/report'

API_KEY = 'cdccfa9dc48fcfd4e39598112a100f8d268caab1cdfcc9a3e0fedc4dbd757151'


def query_api(hash_value):
    	"""Query VirusTotal's API based on a given hash value"""
	try:
		params = {'apikey': API_KEY, 'resource': hash_value}
		response = requests.get(URL, params=params)
		results = response.json()
		fortinet_detect_name = results['scans']['Fortinet']['result']
		num_detect_eng = int(sum(
			[1 if results['scans'][x]['result'] else 0 for x in results['scans']]))
		scan_date = results['scan_date']
		return fortinet_detect_name, num_detect_eng, scan_date
	except:
		return 'None', 'None', 'None'


def retrieve_report(uploaded_file_path):
	"""Read uploaded file and return report as a dataframe"""
	df = pd.read_csv(uploaded_file_path, header=None,
					 names=['hash_value (MD5 or Sha256)'])
	ft_list, num_eng_list, scan_dt_list = [], [], []
	for i in range(len(df)):
		ft_nm, num_eng, scan_dt = query_api(
			df['hash_value (MD5 or Sha256)'][i])
		ft_list.append(ft_nm)
		num_eng_list.append(num_eng)
		scan_dt_list.append(scan_dt)
		time.sleep(15)
	df['Dectection name'] = ft_list
	df['Number of engines detected'] = num_eng_list
	df['Scan Date'] = scan_dt_list
	return df


def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in 'txt'


