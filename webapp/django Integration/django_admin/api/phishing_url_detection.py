import ipaddress
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests


class DETECTION:
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"

    @staticmethod
    def get_domain(url):  # 1. Domain of the URL
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    @staticmethod
    def having_ip(url):
        try:
            ipaddress.ip_address(urlparse(url).netloc)
            return 1
        except ValueError:
            return 0

    @staticmethod
    def have_at_sign(url):
        return 1 if "@" in url else 0

    @staticmethod
    def get_length(url):
        return 1 if len(url) >= 54 else 0

    @staticmethod
    def get_depth(url):
        return len([segment for segment in urlparse(url).path.split('/') if segment])

    @staticmethod
    def redirection(url):
        return 1 if url.find('//') > 6 else 0

    @staticmethod
    def http_domain(url):
        return 0 if urlparse(url).scheme == 'https' else 1

    def tiny_url(self, url):
        return 1 if re.search(self.shortening_services, url) else 0

    @staticmethod
    def prefix_suffix(url):
        if '-' in url:
            return 1
        return 0

    @staticmethod
    def web_traffic(url):
        try:
            encoded_url = urllib.parse.quote(url)
            response = urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={encoded_url}")
            xml_data = response.read()
            soup = BeautifulSoup(xml_data, "xml")
            reach = soup.find("REACH")
            if reach is None or 'RANK' not in reach.attrs:
                return 1
            rank = int(reach['RANK'])
            return 1 if rank < 100000 else 0
        except Exception:
            return 1

    @staticmethod
    def domain_age(domain_info):
        try:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            creation_datetime = datetime.strptime(str(creation_date), "%Y-%m-%d %H:%M:%S")
            current_date = datetime.now()
            age_of_domain_months = (current_date.year - creation_datetime.year) * 12 + current_date.month - creation_datetime.month
            return 0 if age_of_domain_months >= 6 else 1
        except Exception:
            return 1

    @staticmethod
    def domain_end(domain_info):
        try:
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if expiration_date is None:
                return 1
            days_until_expiration = (expiration_date - datetime.now()).days
            return 1 if days_until_expiration < 120 else 0
        except Exception:
            return 1

    @staticmethod
    def iframe(response):
        if response == "":
            return 1
        return 0 if re.findall(r"<iframe>|<frameBorder>", response.text) else 1

    @staticmethod
    def mouse_over(response):
        if response == "":
            return 1
        return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

    @staticmethod
    def right_click(response):
        try:
            if '<button' in response.text:
                return 0
            return 1
        except:
            return 1
    @staticmethod
    def forwarding(response):
        if response == "":
            return 1
        return 0 if len(response.history) <= 2 else 1

    # Function to extract features
    def feature_extractions(self, url):
        features = [
            self.get_domain(url),
            self.having_ip(url),
            self.have_at_sign(url),
            self.get_length(url),
            self.get_depth(url),
            self.redirection(url),
            self.http_domain(url),
            self.prefix_suffix(url),
            self.tiny_url(url)
        ]

        try:
            domain_info = whois.whois(url)
            dns = 0
        except Exception:
            dns = 1

        features.append(dns)
        features.append(1 if dns == 1 else self.web_traffic(url))
        features.append(1 if dns == 1 else self.domain_age(domain_info))
        features.append(1 if dns == 1 else self.domain_end(domain_info))

        try:
            response = requests.get(url)
        except Exception:
            response = ""

        features.append(self.iframe(response))
        features.append(self.mouse_over(response))
        features.append(self.right_click(response))
        features.append(self.forwarding(response))

        return features
