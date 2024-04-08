# EnumIT

This tool was created in order to automate some basic OSINT tasks for penetration testing assingments. The main feature that I haven't seen much anywhere is the downloadd google dork function where this function first perform basic google dorking to find the targets public documents. These documents will then be downloaded to the attackers computer and can be used further to identify metadata about the client.

## Installation

- Create virtual enviroment: `python3 -m venv enumit`
- Activate the virtual enviroment: `source enumit/bin/activate`
- Install the required packages: `pip install -r requirements.txt`

## Basic Usage

### Google Dorking

#### Download the files found

```bash
python3 run.py --domain example.com --google --filetypes pdf --download-files
```

#### Create json list, no download

```bash
python3 run.py --domain example.com --google --filetypes pdf docx jpg
```

#### Certificates

This function will query <https://crt.sh> for the domain name, and create a de-duplicated list for further proccessing.

```bash
python3 run.py --domain example.com --cert
```

### DNS

Perform dns lookup on the domain flag, can be used with the flag `--cert` to find DNS records of subdomains.

```bash
python3 run.py --domain example.com --dns --dns-records A AAAA MX NS
```

### Shodan

In order to use the shodan function, you must have the shodan and api key flag enabled.

```bash
python3 run.py --domain example.com --shodan --shodan-api-key <KEY>
```

### Portscan

This function will take all the ipv4 addresses previsuly found and perform a shodan lookup on them to find open ports. by default, it will only scan the IPv4 address resolved by the `--domain` flag. This flag is recomended if you've used the other functions with it.

```bash
python3 run.py --domain example.com --shodan --shodan-api-key <KEY> --portscan
```

### Bananas

```bash
python3 run.py --domain example.com --cert --dns --dns-types A AAAA NS MX --shodan --shodan-api-key <KEY> --portscan --ssl
```

## Notice

- When you perform a scan, the result will be saved under `.<example.com>\` in the folder.
- You might be ratelimited by google if you use the function heavly.
- Using the portscan function will not quaranty that all ports has been scanned on the host, but will rather give a indication on what to expect on the hosts.
