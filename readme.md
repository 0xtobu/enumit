# EnumIT

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

![pylint workflow](https://github.com/0xtobu/enumit/actions/workflows/pylint.yml/badge.svg)

This tool was created in order to automate some basic OSINT tasks for penetration testing assingments. The main feature that I haven't seen much anywhere is the downloadd google dork function where this function first perform basic google dorking to find the targets public documents. These documents will then be downloaded to the attackers computer and can be used further to identify metadata about the client.

## Installation

- Create virtual enviroment: `python3 -m venv enumit`
- Activate the virtual enviroment: `source enumit/bin/activate`
- Install the required packages: `pip install -r requirements.txt`

## Basic Usage

TODO

## Notice

- When you perform a scan, the result will be saved under `.<example.com>\` in the folder.
- You might be ratelimited by google if you use the function heavly.
- Using the portscan function will not quaranty that all ports has been scanned on the host, but will rather give a indication on what to expect on the hosts.
