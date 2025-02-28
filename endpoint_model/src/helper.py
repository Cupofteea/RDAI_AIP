# Contains some common helper functions. 

import logging
import requests

from urllib3.util import Retry
from requests.adapters import HTTPAdapter

# Logging

def create_logger(logger_name, filename, format, level):
    # create logger with 'spam_application'
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    # create file handler
    fh = logging.FileHandler(filename)
    # create console handler
    ch = logging.StreamHandler()
    # create formatter and add it to the handlers
    formatter = logging.Formatter(format)
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger

#---------------------------------------------------------------
# HTTP requests

DEFAULT_HTTP_TIMEOUT = 10 # seconds

class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_HTTP_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)
    
def request_helper(retries=5, backoff_factor=10, timeout=20, https=True):
    session = requests.Session()

    retry = Retry(
        total=retries,
        status_forcelist=[401, 429, 500, 502, 503, 504],
        backoff_factor=backoff_factor,
        method_whitelist=["GET", "POST"]
    )
    adapter = TimeoutHTTPAdapter(max_retries=retry, timeout=timeout)
    if https:
        session.mount('https://', adapter)
        return session
    else:
        session.mount('http://', adapter)
        return session

# Sending via NLP

def send_through_nlp(url, title, content, lang, models):

    # Input
    raw_data = {
        "title": title,
        "content": content,
        "lang": lang,
        "models": models
        }
    
    data = request_helper(retries=4, backoff_factor=5, timeout=120, https=False).post(url, json=raw_data)

    # Output
    # Results field contains labels, entities and spans extracted from the NLP models.
    """"
    nlp_output_data = {
        "title":,
        "content":,
        "translated_title":,
        "translated_content:,
        "results":{
            "post_classifier": [] of str
        }

    """
    return data.json()

def send_through_heuristics(url, id, report):

    # Input
    raw_data = {
        "id": id,
        "report": report
        }
    
    data = request_helper(retries=4, backoff_factor=5, timeout=120, https=False).post(url, json=raw_data)

    # Output
    # Results field contains labels, entities and spans extracted from the NLP models.
    """"
    nlp_output_data = {
        "attack_type": [],
        "attacker_victim_country": [],
        "ioc": [],
        "malware_tools": [],
        "motivation": [],
        "report_id": "",
        "target_asset_technology": [],
        "threat_actor_name": [],
        "threat_actor_type": [],
        "ttp": [],
        "victim_sector": [],
        "vulnerability": []
    }

    """
    return data.json()

