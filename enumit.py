#!/usr/bin/env python3
"""enumit"""
from absl import app
from absl import logging
from absl import flags
import dns.resolver
import json
import os
import shodan
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

flags.DEFINE_boolean("shodan", False, "perform search for domain names from shodan")

flags.DEFINE_boolean("shodanssl", False, "searches shodan for ssl")

flags.DEFINE_boolean("shodanport", False, "searches shodan for ssl")

flags.DEFINE_string("shodankey", None, "api key for shodan")

flags.DEFINE_boolean("debug", False, "produces debugging output.")

flags.mark_flag_as_required("tldn")


def check_if_json_exist(json_filename):

    if os.path.isfile("./" + FLAGS.tldn + "/" + json_filename + ".json"):
        return True
    else:
        return False


def get_dictonar_from_saved_json(json_filename):
    json_object_to_load = open(
        "./" + FLAGS.tldn + "/" + json_filename + ".json", encoding="utf-8"
    )
    json_object = json.load(json_object_to_load)
    return json_object


def download_file_from_uri(file_uri, download_folder):
    """Download a file from a given URI to a specified download folder.
    Parameters:
        file_uri (str): The URI of the file to download.
        download_folder (str): The local folder path where the file will be saved.

    The function splits the file URI to extract the filename,
    constructs the full path for the file to be saved,
    and attempts to download the file using a GET request. If the request
      is successful and the response status code is 200,
    the file content is written to the specified location in binary mode.
      If the request fails, a warning is logged.
    """
    splitted_uri_by_slash = file_uri.split("/")
    file_save_location = download_folder + "/" + splitted_uri_by_slash[-1]
    response = requests.get(file_uri, timeout=10)

    if not response.status_code == 200:
        logging.warning("could not download %s", file_uri)
        return

    with open(file_save_location, "wb") as file:
        file.write(response.content)


def search_google(filetype_extention):
    """Perform a Google search for files of a specific filetype on a specified site.
    Parameters:
        filetype_extention (str): The filetype extension to search for (pdf)

    Returns:
        list: A list of URIs that match the Google search query.

    The function constructs a Google search query
    using the site specified by the FLAGS.tldn variable
    and the provided filetype extension. It logs the search query, performs the search,
    and appends each resulting URI to a list. If the debug logging level is set,
    the function logs each URI added to the list and the completion of the search.
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
    """Save a dictionary object to a JSON file.
    Parameters:
        filename (str): The name of the file to save the dictionary to.
        dictonary_data (dict): The dictionary object to save.

    The function constructs the full filename by
    appending '.json' to the provided filename,
    and saves it in the directory specified by the FLAGS.tldn variable.
    The dictionary is saved in a human-readable format
    with UTF-8 encoding and an indentation of 2 spaces.

    If the debug logging level is set, the function
    logs the attempt and success of saving the dictionary.
    """
    full_filename = "./" + FLAGS.tldn + "/" + filename + ".json"
    if logging.level_debug():
        logging.debug("attempting to save %s to %s", filename, full_filename)

    with open(full_filename, "w", encoding="utf-8") as f:
        json.dump(dictonary_data, f, ensure_ascii=False, indent=2)
        if logging.level_debug():
            logging.debug("saved %s to %s", filename, full_filename)


def query_dns_server(dns_record, dns_record_type, dnserver="1.1.1.1"):
    """Query a DNS server for a specific record type associated with a DNS record.
    Parameters:
        dns_record (str): The DNS record to query.
        dns_record_type (str):
        The type of DNS record to query for (e.g., 'A')
        dnserver (str): The IP address of the DNS server to query. Defaults '1.1.1.1'

    Returns:
        dns.resolver.Answer:
            An object containing the DNS query resultsif the query was successful.
            None: If the query fails or if there is no answer to the DNS query.

    Raises:
        dns.resolver.NoAnswer: If the DNS query does not have an answer.
        dns.exception.DNSException: For any DNS related exceptions.
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
    """
    Validate if the provided DNS record type is valid.

    Parameters:
    dns_record (str): A string representing the DNS record type to validate.

    Returns:
    bool: True if the DNS record type is valid, False otherwise.
    """
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

    if FLAGS.shodan:
        logging.info("started shodan module")

        if logging.level_debug():
            logging.debug("checking if API key is provided")

        if os.environ.get("SHODAN_API_KEY"):
            logging.info("api key provided via enviroment variable")
            shodan_api_key = os.environ.get("SHODAN_API_KEY")

        elif FLAGS.shodankey:
            logging.info("api key provided via argument")
            shodan_api_key = FLAGS.shodankey

        else:
            logging.warning("no api key provided")
            return

        shodan_api = shodan.Shodan(shodan_api_key)
        if logging.level_debug():
            logging.debug("api key that will be used: %s", shodan_api.api_key)

        logging.info("shodan ready for use")

    if FLAGS.shodanssl and FLAGS.shodan:
        logging.info("started shodan SSL module")

        shodan_ssl_query = str("ssl:%s", FLAGS.tldn)

        if logging.level_debug():
            logging.debug("shodan query: %s", shodan_ssl_query)

        shodan_ssl_results = shodan_api.search(shodan_ssl_query)
        save_dict_to_json("shodan-ssl-results", shodan_ssl_results["matches"])

    elif FLAGS.shodanssl and not FLAGS.shodan:
        logging.info("ssl module requires --shodan")

    if FLAGS.shodanport:
        logging.info("started shodan SSL module")

        check_dns_cache = check_if_json_exist("dns-data")

        shodan_ipv4_addresses_list = []

        if check_dns_cache:
            logging.info("found cached data, using that")
            cached_dns_records = get_dictonar_from_saved_json("dns-data")
            shodan_ipv4_addresses_list = [
                record
                for cached_record in cached_dns_records["dns"]
                if cached_record["records"]["A"]
                for item in cached_record["records"]["A"]
                for record in item
            ]

        elif check_dns_cache is False:
            logging.info("cache not found, will query A record for %s", FLAGS.tldn)

            shodan_dns_server_response = query_dns_server(FLAGS.tldn, "A")
            if shodan_dns_server_response is not None:
                if logging.level_debug():
                    logging.debug(
                        "%s at %s returned non-none value",
                        "A",
                        FLAGS.tldn,
                    )
                    logging.debug("adding %s record to list", FLAGS.tldn)

                for response in shodan_dns_server_response:
                    shodan_ipv4_addresses_list.append(str(response))

        shodan_results = {}

        for shodan_ipv4_address_to_search in shodan_ipv4_addresses_list:
            query = str("net:%s", shodan_ipv4_address_to_search)
            logging.info("searching shodan for: %s", query)

            result = shodan_api.search(query)
            shodan_results[shodan_ipv4_address_to_search] = result

        save_dict_to_json("shodan-results-ipv4-from-domain", shodan_results)

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

        for filetype in google_uri_results.items():  # [consider-using-dict-items]
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
