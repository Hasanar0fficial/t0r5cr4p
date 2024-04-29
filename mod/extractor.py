#!/usr/bin/python
import io
import os
import urllib.error
import urllib.parse
import urllib.request
from urllib.error import HTTPError
from urllib.error import URLError
from http.client import InvalidURL
from http.client import IncompleteRead

from bs4 import BeautifulSoup


def text(response=None):
    """ Removes all the garbage from the HTML and takes only text elements
    from the page.
    """
    soup = BeautifulSoup(response, features="lxml")
    for s in soup(['script', 'style']):
        s.decompose()

    return ' '.join(soup.stripped_strings)

def check_yara(raw=None, yara=0):
    """ Validates Yara Rule to categorize the site and check for keywords.
    """

    try:
        import yara as _yara
    except OSError:
        print("YARA module error: " + 
              "Try this solution: https://stackoverflow.com/a/51504326")

    file_path = os.path.join('res/keywords.yar')

    if raw is not None:
        if yara == 1:
            raw = text(response=raw).lower()

        file = os.path.join(file_path)
        rules = _yara.compile(file)
        matches = rules.match(data=raw)
        if len(matches) != 0:
            print("YARA: Found a match!")
        return matches


def cinex(input_file, out_path, yara=None):
    """ Ingests the crawled links from the input_file,
    scrapes the contents of the resulting web pages and writes the contents to
    the into out_path/{url_address}.
    """
    file = io.TextIOWrapper
    try:
        file = open(input_file, 'r')
    except IOError as err:
        print(f"Error: {err}\n## Can't open: {input_file}")

    for line in file:

        # Generate the name for every file.
        try:
            page_name = line.rsplit('/', 1)
            cl_page_name = str(page_name[1])
            cl_page_name = cl_page_name[:-1]
            if len(cl_page_name) == 0:
                output_file = "index.htm"
            else:
                output_file = cl_page_name
        except IndexError as error:
            print(f"Error: {error}")
            continue

        # Extract page to file.
        try:
            content = urllib.request.urlopen(line, timeout=10).read()

            if yara is not None:
                full_match_keywords = check_yara(content, yara)

                if len(full_match_keywords) == 0:
                    print('No matches found.')
                    continue

            with open(out_path + "/" + output_file, 'wb') as results:
                results.write(content)
            print(f"# File created on: {os.getcwd()}/{out_path}/{output_file}")
        except HTTPError as e:
            print(f"Cinex Error: {e.code}, cannot access: {e.url}")
            continue
        except InvalidURL as e:
            print(f"Invalid URL: {line} \n Skipping...")
            continue
        except IncompleteRead as e:
            print(f"IncompleteRead on {line}")
            continue
        except IOError as err:
            print(f"Error: {err}\nCan't write on file: {output_file}")
    file.close()


def intermex(input_file, yara):
    """ Input links from file and extract them into terminal.
    """
    try:
        with open(input_file, 'r') as file:
            for line in file:
                content = urllib.request.urlopen(line).read()
                if yara is not None:
                    full_match_keywords = check_yara(raw=content, yara=yara)

                    if len(full_match_keywords) == 0:
                        print(f"No matches in: {line}")
                print(content)
    except (HTTPError, URLError, InvalidURL) as err:
        print(f"Request Error: {err}")
    except IOError as err:
        print(f"Error: {err}\n## Not valid file")


def outex(website, output_file, out_path, yara):
    """ Scrapes the contents of the provided web address and outputs the
    contents to file.
    """
    # Extract page to file
    try:
        output_file = out_path + "/" + output_file
        content = urllib.request.urlopen(website).read()

        if yara is not None:
            full_match_keywords = check_yara(raw=content, yara=yara)

            if len(full_match_keywords) == 0:
                print(f"No matches in: {website}")

        with open(output_file, 'wb') as file:
            file.write(content)
        print(f"## File created on: {os.getcwd()}/{output_file}")
    except (HTTPError, URLError, InvalidURL) as err:
        print(f"HTTPError: {err}")
    except IOError as err:
        print(f"Error: {err}\n Can't write on file: {output_file}")


def termex(website, yara):
    """ Scrapes provided web address and prints the results to the terminal.
    """
    try:
        content = urllib.request.urlopen(website).read()
        if yara is not None:
            full_match_keywords = check_yara(content, yara)

            if len(full_match_keywords) == 0:
                # No match.
                print(f"No matches in: {website}")
                return

        print(content)
    except (HTTPError, URLError, InvalidURL) as err:
        print(f"Error: ({err}) {website}")
        return


def extractor(website, crawl, output_file, input_file, out_path, selection_yara):
    """ Extractor - scrapes the resulting website or discovered links.
    """
    # TODO: Return output to torcrawl.py
    if len(input_file) > 0:
        if crawl:
            cinex(input_file, out_path, selection_yara)
        # TODO: Extract from list into a folder
        # elif len(output_file) > 0:
        # 	inoutex(website, input_ile, output_file)
        else:
            intermex(input_file, selection_yara)
    else:
        if len(output_file) > 0:
            outex(website, output_file, out_path, selection_yara)
        else:
            termex(website, selection_yara)
