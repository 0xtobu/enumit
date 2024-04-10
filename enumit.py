#!/usr/bin/env python3
"""enumit"""
from absl import app
from absl import logging
from absl import flags
import dns.resolver
import json
import os
from pycrtsh import Crtsh as crtsh
from googlesearch import search
import requests

enumit_version_number = "v2.0.1"

FLAGS = flags.FLAGS

flags.DEFINE_string("tldn", None, "The domain name you want to enumerate")

flags.DEFINE_list("dnsrecord", None, "DNS record you want to query")

flags.DEFINE_string("dnserver", "1.1.1.1", "the DNS server to use")

flags.DEFINE_boolean("crtsh", False, "queries CRT.SH for certificate information")

flags.DEFINE_list(
    "google",
    None,
    "performs google dorking against tldn with provided file extentions",
)
flags.DEFINE_boolean("download", False, "downloads the results from google")

flags.DEFINE_boolean("debug", False, "produces debugging output.")

flags.mark_flag_as_required("tldn")


def download_file_from_uri(file_uri, download_folder):
    splitted_uri_by_slash = file_uri.split("/")
    file_save_location = download_folder + "/" + splitted_uri_by_slash[-1]
    response = requests.get(file_uri, timeout=10)

    if not response.status_code == 200:
        logging.warning("could not download %s", file_uri)
        return

    with open(file_save_location, "wb") as file:
        file.write(response.content)


def search_google(filetype_extention):
    """google search with user supplied file extention
    Args:
      filetype_extention: string
    Return:
      list
    """

    file_uri = []
    google_query = f"site:{FLAGS.tldn} filetype:{filetype_extention}"

    if logging.level_debug():
        logging.debug("started google search function")
    logging.info("searching google for: %s", google_query)

    google_results = search(query=google_query)

    for uri in google_results:
        if logging.level_debug():
            logging.debug("adding uri to list: %s", uri)
        file_uri.append(uri)

    if logging.level_debug():
        logging.debug("%s search completed, returing list", filetype_extention)
    return file_uri


def crtsh_search():
    # TODO(contact.me@tobu.tech): add doc string
    crt = crtsh()
    certs = crt.subdomains(FLAGS.tldn)
    return certs


def save_dict_to_json(filename: str, dictonary_data: dict):
    """saves python dictonaries into a json file
    Args:
      filename: must be a string, hopefully identifiable
      dictonary_data: the data you want saved
    Returns:
      Does not return any data
    """

    full_filename = "./" + FLAGS.tldn + "/" + filename + ".json"
    if logging.level_debug():
        logging.debug("attempting to save %s to %s", filename, full_filename)

    with open(full_filename, "w", encoding="utf-8") as f:
        json.dump(dictonary_data, f, ensure_ascii=False, indent=2)
        if logging.level_debug():
            logging.debug("saved %s to %s", filename, full_filename)


def query_dns_server(dns_record, dns_record_type, dnserver="1.1.1.1"):
    """queries a DNS server for information
    Args:
      dns_record: domain name as string that should to queried, i.e example.com
      dns_record_type:  record type, examples are: A,AAAA,NS,TXT
      dnserver:  DNS server you want to use
    Returns:
      object
      none if no data was found for the spesific record type
    """

    if logging.level_debug():
        logging.debug("reached function query_dns_server")
        logging.debug(
            "query for %s towards %s at %s",
            dns_record_type,
            dns_record,
            dnserver,
        )

    try:
        dns_results = dns.resolver.resolve(dns_record, dns_record_type)
        if logging.level_debug():
            logging.debug("got following reponse: %s", dns_results.response.answer)

        return dns_results

    except (dns.resolver.NoAnswer, dns.exception.DNSException) as answer:
        if logging.level_debug():
            logging.debug(answer)
        return None


def validate_dns_record(dns_record):
    if logging.level_debug():
        logging.debug("validate_dns_record function started")
    valid_records = ["A", "CNAME", "AAAA", "NS", "TXT"]

    if dns_record in valid_records:
        if logging.level_debug():
            logging.debug("valid record: %s", dns_record)
        return True
    else:
        if logging.level_debug():
            logging.debug("invalid record: %s", dns_record)
        return False


def main(argv):
    del argv  # Unused.

    logging.info("started enumit version: %s", enumit_version_number)

    if FLAGS.debug:
        logging.set_verbosity(logging.DEBUG)
        logging.debug("debug enabled")


    if not os.path.isdir("./" + FLAGS.tldn):
        logging.info("new client detected, creating client folder: %s", FLAGS.tldn)
        os.mkdir(FLAGS.tldn)

    fqdn_list = []
    fqdn_list.append(FLAGS.tldn)

    if FLAGS.crtsh:
        if logging.level_debug():
            logging.debug("using crtsh to find subdomains for %s", FLAGS.tldn)

        crtsh_domain_object = {}
        crtsh_domains = crtsh_search()
        crtsh_domain_object[FLAGS.tldn] = crtsh_domains

        for domain in crtsh_domains:
            if logging.level_debug():
                logging.debug("adding %s to fqdn_list", domain)
            fqdn_list.append(domain)

        save_dict_to_json("crtsh-domains", crtsh_domain_object)

    if FLAGS.google:
        if logging.level_debug():
            logging.debug("google flag is set to true, starting google dorking")

        google_uri_results = {}

        for google_search_filetype in FLAGS.google:
            results = search_google(google_search_filetype)
            google_uri_results[google_search_filetype] = results

        save_dict_to_json("google-files", google_uri_results)

    if FLAGS.download:
        if logging.level_debug():
            logging.debug("download flag is set, will attempt to download")

        download_directory = "./" + FLAGS.tldn + "/google-scraped-documents"

        if not os.path.isdir(download_directory):
            logging.info(
                "no download folder located, creating a new one: %s",
                download_directory,
            )
            os.mkdir(download_directory)

        for filetype in google_uri_results:
            for uri in google_uri_results[filetype]:
                download_file_from_uri(uri, download_directory)

    if FLAGS.dnsrecord:
        if logging.level_debug():
            logging.debug("start query following types: %s", FLAGS.dnsrecord)

        for dns_record in FLAGS.dnsrecord:
            if logging.level_debug():
                logging.debug(
                    "checking if %s is valid DNS record type", FLAGS.dnsrecord
                )

            if not validate_dns_record(dns_record):
                logging.error("%s is not a valid DNS record", dns_record)
                return

        if logging.level_debug():
            logging.debug("all records are valid, contiunue to query DNS server")

        domain_names_list = {"dns": []}

        for fqdn in fqdn_list:

            temp_object = {}
            temp_object["kind"] = "dns#resourceRecordSet"
            temp_object["name"] = fqdn
            temp_object["records"] = {}

            for record in FLAGS.dnsrecord:
                temp_object["records"][record] = []

            domain_names_list["dns"].append(temp_object)

        # for a in domain_names_list["dns"]:
        #    print(a["name"])

        for fqdn in domain_names_list["dns"]:
            if logging.level_debug():
                logging.debug("started for loop over fqdn: %s ", fqdn["name"])

            for record in fqdn["records"]:

                if logging.level_debug():
                    logging.debug(
                        "attempting to query %s record for %s",
                        record,
                        fqdn["name"],
                    )

                dns_server_response = query_dns_server(fqdn["name"], record)
                dns_results = []

                if dns_server_response is not None:
                    if logging.level_debug():
                        logging.debug(
                            "%s at %s returned non-none value",
                            record,
                            fqdn["name"],
                        )
                        logging.debug("adding %s record to list", record)

                    for response in dns_server_response:
                        dns_results.append(str(response))

                    if logging.level_debug():
                        logging.debug("adding %s output to dns_results", dns_results)

                    fqdn["records"][record].append(dns_results)

            save_dict_to_json("dns-data", domain_names_list)


if __name__ == "__main__":
    app.run(main)
