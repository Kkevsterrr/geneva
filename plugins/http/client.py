"""
Run by the evaluator, tries to make a GET request to a given server
"""

import argparse
import os
import socket
import urllib.request
import requests

from plugins.plugin_client import ClientPlugin

socket.setdefaulttimeout(1)

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
        parser.add_argument('--injected-http-contains', action='store',
                            default="", help='checks if injected http response contains string')
        parser.add_argument('--valid-http-contains', action='store',
                            default="", help='checks if http response contains the given string. '
                                             'if not, the connection is evaluated as broken')

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
            url += f":{str(port)}"

        if args.get("bad_word"):
            url += f"?q={args.get('bad_word')}"

        try:
            res = requests.get(url, allow_redirects=False, timeout=3, headers=headers)
            logger.debug(res.text)
            # If we need to monitor for an injected response, check that here
            if args.get("injected_http_contains") and args.get("injected_http_contains") in res.text:
                fitness -= 90
            elif args.get("valid_http_contains"):
                if args.get("valid_http_contains") in res.text:
                    # valid response found
                    fitness += 100
                else:
                    fitness -= 120
                    logger.debug("valid response needed, but not found -> connection broke\n")
            else:
                fitness += 100
        except requests.exceptions.ConnectTimeout:
            logger.exception("Socket timeout.")
            fitness -= 100
        except (requests.exceptions.ConnectionError, ConnectionResetError):
            logger.exception("Connection RST.")
            fitness -= 90
        except urllib.error.URLError as exc:
            logger.debug(exc)
            fitness -= 101
        # Timeouts generally mean the strategy killed the TCP stream.
        # HTTPError usually mean the request was destroyed.
        # Punish this more harshly than getting caught by the censor.
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as exc:
            logger.debug(exc)
            fitness -= 120
        except Exception:
            logger.exception("Exception caught in HTTP test to site %s.", url)
            fitness -= 100
        return fitness * 4
