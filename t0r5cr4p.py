#!/usr/bin/python

import argparse
import os
import socket
import sys
import datetime

import socks  # noqa - pysocks

from mod.checker import check_ip
from mod.checker import check_tor
from mod.checker import extract_domain
from mod.checker import folder
from mod.checker import url_canon
# Modules for tor crawling
from mod.crawler import Crawler
from mod.extractor import extractor


# Set socket and connection with TOR network
def connect_tor():
    """ Connect to TOR via DNS resolution through a socket.
    :return: None or HTTPError.
    """
    try:
        port = 9050
        # Set socks proxy and wrap the urllib module
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', port)
        socket.socket = socks.socksocket

        # Perform DNS resolution through the socket
        def getaddrinfo(*args):  # noqa
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '',
                     (args[0], args[1]))]

        socket.getaddrinfo = getaddrinfo  # noqa
    except socks.HTTPError as err:
        error = sys.exc_info()[0]
        print(f"Error: {error} \n## Cannot establish connection with TOR\n"
              f"HTTPError: {err}")


def main():
    """ Main method of TorCrawl application. Collects and parses arguments and
    instructs the rest of the application on how to run.

    :return: None
    """

    # Get arguments with argparse.
    parser = argparse.ArgumentParser(
        description="t045cr4p is a python script to crawl and extract(SCRAPE) "
                    "(regular or onion) webpages through TOR network by Hasanar0fficial.")

    # General
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Show more information about the progress'
    )
    parser.add_argument(
        '-u',
        '--url',
        help='URL of webpage to crawl or extract'
    )
    parser.add_argument(
        '-w',
        '--without',
        action='store_true',
        help='Without tor connection'
    )

    # Extract
    parser.add_argument(
        '-e',
        '--extract',
        action='store_true',
        help='Extract page\'s code to terminal or file.'
    )
    parser.add_argument(
        '-i',
        '--input',
        help='Input file with URL(s) (separated by line)'
    )
    parser.add_argument(
        '-o',
        '--output',
        help='Output page(s) to file(s) (for one page)'
    )

    # Crawl
    parser.add_argument(
        '-c',
        '--crawl',
        action='store_true',
        help='Crawl website (Default output on /links.txt)'
    )
    parser.add_argument(
        '-l',
        '--log',
        action='store_true',
        help='A save log will let you see which URLs were visited and their '
             'response code'
    )
    parser.add_argument(
        '-f',
        '--folder',
        help='The root directory which will contain the generated files'
    )
    parser.add_argument(
        '-y',
        '--yara',
        help='Check for keywords and only scrape documents that contain a '
             'match. \'h\' search whole html object. \'t\' search only the text.'
    )

    args = parser.parse_args()

    # Debugging print
    print("URL:", args.url)

    # Parse arguments to variables else initiate variables.
    input_file = args.input if args.input else ''
    output_file = args.output if args.output else ''
    selection_yara = args.yara if args.yara else None

    # Connect to TOR
    if args.without is False:
        check_tor(args.verbose)
        connect_tor()

    if args.verbose:
        check_ip()
        print(('## URL: ' + args.url))

    website = ''
    out_path = ''

    # Canonicalization of web url and create path for output.
    if args.url and len(args.url) > 0:
        website = url_canon(args.url, args.verbose)
        if args.folder is not None:
            out_path = folder(args.folder, args.verbose)
        else:
            out_path = folder(extract_domain(website), args.verbose)

    if args.crawl:
        crawler = Crawler(website, out_path, args.log, args.verbose)
        lst = crawler.crawl()

        now = datetime.datetime.now().strftime("%Y%m%d")
        with open(out_path + '/' + now + '_links.txt', 'w+', encoding='UTF-8') as file:
            for item in lst:
                file.write(f"{item}\n")
        print(f"## File created on {os.getcwd()}/{out_path}/links.txt")

        if args.extract:
            input_file = out_path + "/links.txt"
            extractor(website, args.crawl, output_file, input_file, out_path,
                      selection_yara)
    else:
        extractor(website, args.crawl, output_file, input_file, out_path,
                  selection_yara)


# Stub to call main method.
if __name__ == "__main__":
    main()
