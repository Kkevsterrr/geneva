"""
Client

Run by the evaluator, echo's data back and forth to the server
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

import actions.utils

from plugins.plugin_client import ClientPlugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class EchoClient(ClientPlugin):
    """
    Defines the Echo client.
    """
    name = "echo"

    def __init__(self, args):
        """
        Initializes the echo client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        super_args = ClientPlugin.get_args(command)
        parser = argparse.ArgumentParser(description='Echo Client')

        parser.add_argument('--injection-censor', action='store_true', help="whether this censor injects content or sends RSTs to censor")
        parser.add_argument('--server', action='store', help="server to connect to")
        parser.add_argument('--http-request', action='store', help="send an HTTP get request with the given hostname to the echo server")

        args, _ = parser.parse_known_args(command)
        args = vars(args)

        super_args.update(args)
        return super_args

    def run(self, args, logger, engine=None):
        """
        Try to make a forbidden GET request to the server.
        """
        fitness = 0
        port = int(args["port"])
        server = args["server"]
        bad_word = args["bad_word"]
        msg = bad_word
        if args.get("http_request"):
            msg = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % args.get("http_request")
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(10)
            client.connect((server, port))
            for idx in range(0, 5):
                if type(msg) == str:
                    msg = msg.encode()
                client.sendall(msg)
                server_data = client.recv(1024)
                logger.debug("Data recieved: %s", server_data.decode('utf-8', 'ignore'))
                if server_data == msg:
                    fitness += 100
                elif server_data:
                    fitness -= 90
                    break

            client.close()
            # If the fitness is 0, the strategy did something to corrupt/interfere with the socket
            # sending/receiving, usually by just artificially closing the connection. This behavior
            # should not be rewarded with a higher fitness
            if fitness == 0:
                fitness -= 100
        except socket.timeout:
            logger.debug("Client: Timeout")
            fitness -= 100
        except socket.error as exc:
            # If the censor we're running against tears down connects via RSTs, we can punish RSTs as
            # if the strategy did not harm the underlying connection. However, if the censor only injects
            # traffic, not resets, we should punish RSTs harshly, as the strategy likely caused it.

            if exc.errno == 104:
                if args.get("injection_censor"):
                    fitness -= 110
                else:
                    fitness -= 90
                logger.debug("Client: Connection RST.")
            else:
                fitness -= 100
                logger.exception("Socket error caught in client echo test.")
        except Exception:
            logger.exception("Exception caught in client echo test.")
            fitness = -120
        finally:
            logger.debug("Client finished echo test.")
        return fitness * 4
