# -*- coding: utf-8 -*-

from datetime import datetime

import logging
import re
import base64
import gzip
import binascii

def _get_max_len_by_line(message):
	max_len = 0
	for m in message.split('\n'):
		max_len = max(max_len, len(m))

	return max_len

def _get_date(str_time):
	time_formats = ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]
	time = None
	for time_format in time_formats:
		try:
			time = datetime.strptime(str_time, time_format)
			if time:
				break
		except Exception as e:
			print(e)
			pass
	return time

def decode_powershell(raw_payload):
	""" It takes a payload string as input and tries to decode it as powershell payload
		  => This Q&D to decode stager spawned by powershell....
		 It return a tuple containing (Boolean, String), boolean indicates if the process was successful and the string is the decoded payload
	"""
	decoded_payload = ''
	try:
		# TODO: clean this mess...
		if 'JgAoAFsAcwB' in raw_payload or 'JABzAD0A' in raw_payload:
			if '-w hidden -e' not in raw_payload:
				return ('not handle', 'unknown', 'unknown', '')

			if 'encodedcommand' in raw_payload:
				decoded_payload = raw_payload.split('-w hidden -encodedcommand ')[1]
			else:
				decoded_payload = raw_payload.split('-w hidden -e ')[1].split("'")[0]
			
			_tmp = base64.b64decode(decoded_payload).decode('utf16')
			tmp = _tmp.split("'")
			if len(tmp) > 1:
				decoded_payload = tmp[1]
			else:
				decoded_payload = _tmp.split('"')[1]
		elif len(raw_payload.split("''")) == 3:
			decoded_payload = raw_payload.split("''")[1]
		elif 'powershell.exe -ep bypass -w hidden -e ' in raw_payload:
			decoded_payload = raw_payload.split("-w hidden -e")[1].strip()
			decoded_payload = base64.b64decode(decoded_payload).decode('utf16')
		elif 'powershell -nop -exec bypass -EncodedCommand ' in raw_payload:
			decoded_payload = raw_payload.split("-EncodedCommand ")[1].strip()
			decoded_payload = base64.b64decode(decoded_payload).decode('utf16')
		else:
			decoded_payload = raw_payload.split("'")[1]

		decoded_payload = gzip.decompress(base64.b64decode(decoded_payload)).decode()
		
	except Exception as e:
		return (False, decoded_payload)

	return (True, decoded_payload)

def analyze_payload(decoded_powershell):
	re_ip_address = r'.*([0-9]{2,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*'
	re_port = r'.*680200([0-9a-f]{4,4}).*'
	re_port_2 = r'.*bc0200([0-9a-f]{4,4}).*'
	re_port_3 = r'.*c40200([0-9a-f]{4,4}).*'
	regex = re.compile(re_ip_address, re.DOTALL)
	regex_port = re.compile(re_port, re.DOTALL | re.IGNORECASE)
	regex_port_2 = re.compile(re_port_2, re.DOTALL | re.IGNORECASE)
	regex_port_3 = re.compile(re_port_3, re.DOTALL | re.IGNORECASE)


	message = 'unknown'
	ip = ''
	port = ''
	for line in decoded_powershell.split('\n'):
		if 'FromBase64String' in line:
			payload = line.split('"')[1]
			decoded_payload = base64.b64decode(payload).decode('utf8', 'ignore')
			# is_ip = regex.match(decoded_payload)
			is_ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', decoded_payload )

			message = 'unknown'
			ip = ''
			port = ''
			
			if is_ip:
				if 'hwiniThLw&' in decoded_payload and 'hnet' in decoded_payload:
					message = 'reverse HTTP stager to {}'.format(is_ip[0])
				else:
					message = 'reverse stager to {}'.format(is_ip[0])
				ip = is_ip[0]
			else:
				hex_payload = binascii.hexlify(base64.b64decode(payload)).decode()
				is_port = regex_port.match(hex_payload)
				is_port_2 = regex_port_2.match(hex_payload)
				is_port_3 = regex_port_3.match(hex_payload)
				if is_port:
					message = 'bind stager listening on {}'.format(int(is_port.group(1), 16))
					port = int(is_port.group(1), 16)
				elif is_port_2:
					message = 'bind stager listening on {}'.format(int(is_port_2.group(1), 16))
					port = int(is_port_2.group(1), 16)
				elif is_port_3:
					message = 'bind stager listening on {}'.format(int(is_port_3.group(1), 16))
					port = int(is_port_3.group(1), 16)

			if not ip and not port:
				ip = '??'
				port = '??'

	return (message.strip(), ip, port)
