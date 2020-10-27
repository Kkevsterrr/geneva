"""
Run by the evaluator, tries to make a GET request to a given server
"""

import argparse
import logging
import os
import random
import socket
import sys
import time
import traceback
import urllib.request

import requests

socket.setdefaulttimeout(1)

import external_sites
import actions.utils

from plugins.plugin_client import ClientPlugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class HTTPClient(ClientPlugin):
    """
    Defines the HTTP client.
    """
    name = "http"

    def __init__(self, args):
        """
        Initializes the HTTP client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        super_args = ClientPlugin.get_args(command)
        parser = argparse.ArgumentParser(description='HTTP Client', prog="http/client.py")

        parser.add_argument('--host-header', action='store', default="", help='specifies host header for HTTP request')
        parser.add_argument('--injected-http-contains', action='store', default="", help='checks if injected http response contains string')
        parser.add_argument('--empty-reseponse-is-censorship', action='store_true', default="", help='if the injected response is empty and constitutes censorship')

        args, _ = parser.parse_known_args(command)
        args = vars(args)

        super_args.update(args)
        return super_args

    def run(self, args, logger, engine=None):
        """
        Try to make a forbidden GET request to the server.
        """
        fitness = 0
        url = args.get("server", "")
        assert url, "Cannot launch HTTP test with no server"
        if not url.startswith("http://"):
            url = "http://" + url
        headers = {}
        if args.get('host_header'):
            headers["Host"] = args.get('host_header')

        # If we've been given a non-standard port, append that to the URL
        port = args.get("port", 80)
        if port != 80:
            url += ":%s" % str(port)

        if args.get("bad_word"):
            url += "?q=%s" % args.get("bad_word")

        injected_http = args.get("injected_http_contains")
        try:
            res = requests.get(url, allow_redirects=False, timeout=3, headers=headers)
            text = res.text
            if not text and args.get("empty_response_is_censorship"):
                logger.debug("Empty response detected and this has been identified as censorship.")
                fitness -= 90
            else:
                headers = "\r\n".join([k + ": " + v for k, v in res.headers.items()])
                logger.debug("Headers from GET request: %s", str(headers))
                logger.debug("Response from GET request: %s", str(text))
                if injected_http:
                    logger.debug("Checking for '%s' in response", injected_http)
                # If we need to monitor for an injected response, check that here
                if injected_http and injected_http in (headers + text):
                    fitness -= 90
                else:
                    fitness += 100
        except requests.exceptions.ConnectTimeout as exc:
            logger.exception("Socket timeout.")
            fitness -= 100
        except (requests.exceptions.ConnectionError, ConnectionResetError) as exc:
            logger.exception("Connection RST.")
            fitness -= 90
        except urllib.error.URLError as exc:
            logger.debug(exc)
            fitness += -101
        # Timeouts generally mean the strategy killed the TCP stream.
        # HTTPError usually mean the request was destroyed.
        # Punish this more harshly than getting caught by the censor.
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as exc:
            logger.debug(exc)
            fitness += -120
        except Exception:
            logger.exception("Exception caught in HTTP test to site %s.", url)
            fitness += -100
        logger.debug('Returning initial fitness %d' % fitness)
        return fitness * 4
