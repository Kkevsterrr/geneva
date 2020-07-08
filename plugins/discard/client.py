"""
Client

Run by the evaluator, sends data to discard server.

Not usually used for training because in Python it is difficult to distinguish between a successful
strategy and an unsuccessful strategy. This is because in the discard protocol (in a good case),
the client will send data and the server will throw it away (but ACK it).  In a bad case (such as a
failing strategy that breaks the TCP connection), the client sends the data but it does not reach
the server (so it is not ACKed). However, in Python, it is non trivial to distinguish these two
cases, as neither send() nor sendall() will raise a timeout or check if the data that is sent is
ACKed.
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

socket.setdefaulttimeout(10)

import actions.utils

from plugins.plugin_client import ClientPlugin

import signal

BASEPATH = os.path.dirname(os.path.abspath(__file__))


# Sets up timeout signal because currently, sendall does not give a timeout which is making the
# client believe that the connection has not been torn down.
class TimeoutError(Exception):
    """
    Houses a TimeoutError so we can cut off sendall.
    """
    pass

def handle_timeout(signum, frame):
    import errno
    raise TimeoutError(os.strerror(errno.ETIME))


class DiscardClient(ClientPlugin):
    """
    Defines the Discard client.
    """
    name = "discard"

    def __init__(self, args):
        """
        Initializes the discard client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        super_args = ClientPlugin.get_args(command)
        parser = argparse.ArgumentParser(description='Discard Client')

        # If we know whether the censor we are training against injects content, we can optimize the plugin's behavior.
        # Censors that inject content will give us a very clear signal - after we send content, we can use `recv()` to get
        # the response from the censor. Since this is the discard protocol, if we ever receive data, this is from the censor.
        parser.add_argument('--injection-censor', action='store_true', help="whether this censor injects content or sends RSTs to censor")
        parser.add_argument('--server', action='store', help="server to connect to")
        # Makes it easier to craft fake HTTP requests to trip censorship
        parser.add_argument('--http-request', action='store', help="send an HTTP get request with the given hostname to the discard server")

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
        injection_censor = args.get("injection_censor")
        if args.get("http_request"):
            msg = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % args.get("http_request")
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((server, port))
            for idx in range(0, 5):
                if type(msg) == str:
                    msg = msg.encode()

                # Set a 10 second timeout on the socket. Timeouts do not interrupt send() or sendall().
                client.settimeout(10)

                # Manually create a 5 second timeout
                timeout = 5

                # Setup the timeout as a signal alarm
                signal.signal(signal.SIGALRM, handle_timeout)
                signal.alarm(timeout)

                reached_timeout = False
                try:
                    client.send(msg)
                    # Give the alarm time to realize it must go off
                    time.sleep(1)
                except TimeoutError:
                    logger.debug("sendall() timed out")
                    fitness -= 100
                    reached_timeout = True
                finally:
                    signal.alarm(0)

                # If the censor injects content, checks to make sure nothing is sent back from the server.
                # If the recv times out, then the procedure was successful. If injected content is sent back,
                # censorship has occurred.
                if injection_censor:
                    try:
                        server_data = client.recv(1024)
                        logger.debug("Data received: %s", server_data.decode('utf-8', 'ignore'))
                        fitness -= 90
                    except socket.timeout:
                        fitness += 100
                        logger.debug("No data received from a censor.")
                # If the censor is not an injection censor and the connection is not teared down, the strategy
                # is successful.
                else:
                    if idx != 0 and not reached_timeout:
                        fitness += 90
            client.close()
            # If the fitness is 0, the strategy did something to corrupt/interfere with the socket
            # sending/receiving, usually by just artificially closing the connection. This behavior
            # should not be rewarded with a higher fitness
            if fitness == 0:
                fitness -= 100

        except socket.error as exc:
            # If the censor we're running against tears down connects via RSTs, we can punish RSTs as
            # if the strategy did not harm the underlying connection. However, if the censor only injects
            # traffic, not resets, we should punish RSTs harshly, as the strategy likely caused it.

            if exc.errno == 104:
                if injection_censor:
                    fitness -= 110
                else:
                    fitness -= 100
                logger.debug("Client: Connection RST.")
            else:
                fitness -= 100
                logger.exception("Socket error caught in client discard test.")
        except Exception:
            logger.exception("Exception caught in client discard test.")
            fitness = -120
        finally:
            logger.debug("Client finished discard test.")
            signal.alarm(0)
        return fitness * 4

