#!/bin/python3
from pycrtsh import Crtsh
import argparse
import shodan
from googlesearch import search
import urllib.request
import requests
import os
from alive_progress import alive_bar
from progress.spinner import MoonSpinner
import dns.resolver
import json
import datetime
import time

def defaultconverter(o):
  if isinstance(o, datetime.datetime):
      return o.__str__()

def cert_search(fqdn):
	# Searches CRT.sh for certificates and returns it to main.
	c = Crtsh()
	cert_names = c.search(fqdn)
	domain_names = []
	certificate_list = {}
	certificate_list['certs'] = cert_names
	save_dict_as_json(json.loads(json.dumps(certificate_list, default=str, ensure_ascii=False)),'crt_certificates', fqdn)
	for cert_name in cert_names: 
		if "\n" in cert_name['name']:
			splitted_name = cert_name['name'].split('\n')
			for name in splitted_name:
				if "*." in name:
					a = name.replace('*.', '')
					domain_names.append(a)

		elif "*." in cert_name['name']:
			a = cert_name['name'].replace('*.', '')
			domain_names.append(a)

		else:
			domain_names.append(cert_name['name'])
			
	return list(dict.fromkeys(domain_names))

def download_file_from_url(domain, url, folder):
	data = requests.get(url)
	a = url.split('/')
	base_dir = domain[0] + '/' + folder
	local_path = base_dir + '/' + a[-1]
	if not os.path.isdir(base_dir):
		os.mkdir(base_dir)

	with open(local_path, 'wb')as file:
		file.write(data.content)

def google_dorking(domain_name, filetype_arg): 
	file_links = []
	query = 'site:' + domain_name + ' filetype:' + filetype_arg

	print('[*] Searching google with the following dork: ' + query)
	with MoonSpinner('[*] Googling like a boss, Processing ') as bar:
		for j in search(query):
			file_links.append(j)
			bar.next()

	return file_links

def save_list_to_disk(lst, file_name, domain):
	print('[*] Saving list to disk: ' + "./" + domain + "/" + file_name + ".txt")
	textfile = open("./" + domain + "/" + file_name + ".txt", "w")
	for element in lst:
		textfile.write(element + "\n")

	textfile.close()
	print('[!] Saved!')
	return True

def save_dict_as_json(dictonary, file_name, domain):
	path = './' + domain + "/json"
	if not os.path.isdir(path):
		print('[!] Domain has not been searched for, creating folder for client')
		os.mkdir(path)

	with open(path + "/" + file_name + ".json", "w") as outfile:
		json.dump(dictonary, outfile, indent=2)

	return True


def dns_queries(domain, record_type):
	print('[*] Checking the following record type:', record_type)
	target={}
	with alive_bar(domain.count(domain)) as bar:	
		for i in domain:
			target[i] = {}
			for a in record_type:
				try:		
					value = dns.resolver.resolve(i, a)
					target[i][a] = []
					for val in value:
						target[i][a].append(str(val))
	
				except:
					pass

			bar()

	save_dict_as_json(target,'DNS_Queries', domain[0])	
	return target
		
def shodan_host_search(ipv4_address, api_key):
	api = shodan.Shodan(api_key)
	host = api.host(ipv4_address)
	print(host['ip_str'],host.get('org', 'n/a'))
	return host['ip_str'],host.get('org', 'n/a')

def shodan_ssl_search(domain_name, api_key):
	api = shodan.Shodan(api_key)
	query = 'ssl:"{}"'.format(domain_name)
	result = api.search(query)
	return result['matches']

def shodan_port_search(ipv4_address, api_key):
	api = shodan.Shodan(api_key)
	query = 'net:"{}"'.format(ipv4_address)

	result = api.search(query)

	output = {}
	ports = []
	for i in result['matches']:
		ports.append(i['port'])

	output[ipv4_address] = ports

	return output


def main(args):
	print('Testing against: ' + args.domain)
	print(''' _____                     _____ _____ 
|  ___|                   |_   _|_   _|
| |__ _ __  _   _ _ __ ___  | |   | |  
|  __| '_ \| | | | '_ ` _ \ | |   | |  
| |__| | | | |_| | | | | | || |_  | |  
\____/_| |_|\__,_|_| |_| |_\___/  \_/  
                                       
                                       ''')
	domain_names = []
	domain_names.append(args.domain)
	ipv4_a = []
	hostnames = {}

	if not os.path.isdir('./' + args.domain):
		print('[!] Domain has not been searched for, creating folder for client')
		os.mkdir(args.domain)

	if args.cert:
		print('[!] Checking Certificates') 
		results = cert_search(args.domain)
		for a in results:
			domain_names.append(a)

		save_list_to_disk(domain_names, 'crt_domains', args.domain)

	if args.dns:
		dns_records = dns_queries(domain_names, args.dns_types)
		for i in dns_records:
			for k in dns_records[i]:
				for a in dns_records[i][k]:
					if a in ipv4_a:
						pass
					else:
						ipv4_a.append(a)

	print(ipv4_a)
		
	if args.shodan:
		if args.api_key:
			try:
				if args.providers:
					providers = {}
					for i in ipv4_a:
						try:
							shodan_host_search(i, args.api_key)

						except:
							pass
				
				if args.ssl:
					ssl_hosts = shodan_ssl_search(args.domain, args.api_key)
					shodan_hosts = []
					for i in ssl_hosts:
						if i['ip_str'] in ipv4_a:
							pass

						else: 
							ipv4_a.append(i['ip_str'])
							shodan_hosts.append(i['ip_str'])

					save_dict_as_json(ssl_hosts,'Shodan_SSL_hosts', args.domain)
					save_list_to_disk(shodan_hosts, 'Shodan_SSL_Hosts', args.domain)

				if args.portscan:
					hostnames['hostname'] = []


					with alive_bar(ipv4_a.count(ipv4_a)) as bar:
						for i in ipv4_a:

							hostnames['hostname'].append(shodan_port_search(i, args.api_key))
							time.sleep(1.0)
							bar()

					print(hostnames)
					save_dict_as_json(hostnames,'Shodan_Ports_hosts', args.domain)

			except Exception as e:
				print('[!] Shodan Exception', e)

		else:
			print('[!] You must supply a API key to use the shodan functions.')

	if args.google:
		files = {}
		for i in args.filetypes:
			files[i] = []
			filea = google_dorking(args.domain, i)
			for a in filea:
				files[i].append(a)

		save_dict_as_json(files,'Google_files', args.domain)

def start_page():
	version = 'Version: 0.0.1'
	developer = 'Tobias'
	logo = ''' _____                     _____ _____ 
|  ___|                   |_   _|_   _|
| |__ _ __  _   _ _ __ ___  | |   | |  
|  __| '_ \| | | | '_ ` _ \ | |   | |  
| |__| | | | |_| | | | | | || |_  | |  
\____/_| |_|\__,_|_| |_| |_\___/  \_/  
                                       
                                       '''
	print(logo)
	print(version)
	print(developer)
	print('Twitter: @iface_tobu')


if __name__ == '__main__':
	start_page()

	# Arguments parsed 
	parser = argparse.ArgumentParser(description='Perform basic enumeration with various OSINT teqnuqies.')

	# Required Arguments
	parser.add_argument('--domain', type=str, help='The FQDN (Fully Qualified Domain Name) of the client.', required=True)

	# Shodan Related Arguments
	group = parser.add_argument_group('Shodan Search Settings')
	group.add_argument('--shodan', default=False, action='store_true' , help='Perform shodan searches')
	group.add_argument('--api-key', help='Your shodan API key')
	group.add_argument('--ssl',default=False, action='store_true'  ,help='Discover hosts with the clients FQDN')
	group.add_argument('--portscan',default=False, action='store_true', help='Using the IPv4 addresses to search for open ports')
	group.add_argument('--providers',default=False, action='store_true', help='Tries to identify possible service providers for the client.')

	# Google Dorking
	dorking = parser.add_argument_group('Google Dorking Settings')
	dorking.add_argument('--google',default=False, help='Enables the google dorking module', action='store_true')
	dorking.add_argument('--download-files', action='store_true' ,default=False, help='Dowloads the files found with file searching modules.' )
	dorking.add_argument('--filetypes', default=['pdf','docx', 'doc'], nargs="+", help='Spesify the types of files that you want to search for, default: doc, docx, pdf.')

	# DNS Queries
	dnnns = parser.add_argument_group('DNS Queries settings')
	dnnns.add_argument('--dns', action='store_true' ,default=False, help='Enables the DNS Search functions')
	dnnns.add_argument('--dns-srv', default='1.1.1.1', help='Spesify what DNS server you want to use for DNS Queries. Default is 1.1.1.1')
	dnnns.add_argument('--dns-types', default=['A','NS'], nargs="+", help='Spesify the types of records that you want to search for, default: A, NS. Example:')

	parser.add_argument('--cert', action='store_true',default=False, help='Queries crt.sh for domain names')
	
	args = parser.parse_args()

	# Starting
	try:
		main(args)

	except Exception as e:

		print('[!] Unknown Exception', e)
