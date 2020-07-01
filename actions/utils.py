import copy
import datetime
import importlib
import inspect
import logging
import os
import string
import sys
import random
import urllib.parse
import re
import socket
import random
import struct

import actions.action
import actions.trigger
import actions.packet

from scapy.all import TCP, IP, UDP, rdpcap
import netifaces


RUN_DIRECTORY = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

# Hard coded options
FLAGFOLDER = "flags"

# Holds copy of console file handler's log level
CONSOLE_LOG_LEVEL = logging.DEBUG


BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASEPATH)


def parse(requested_trees, logger):
    """
    Parses a string representation of a solution into its object form.
    """
    # First, strip off any hanging quotes at beginning/end of the strategy
    if requested_trees.startswith("\""):
        requested_trees = requested_trees[1:]
    if requested_trees.endswith("\""):
        requested_trees = requested_trees[:-1]

    # Define a blank strategy to initialize with the user specified string
    strat = actions.strategy.Strategy([], [])

    # Actions for the in and out forest are separated by a "\/".
    # Split the given string by this token
    out_in_actions = requested_trees.split("\\/")

    # Specify that we're starting with the out forest before we parse the in forest
    out = True
    direction = "out"
    # For each string representation of the action directions, in or out
    for str_actions in out_in_actions:
        # Individual action trees always end in "|" to signify the end - split the
        # entire action sequence into individual trees
        str_actions = str_actions.split("|")

        # For each string representation of each tree in the forest
        for str_action in str_actions:
            # If it's an empty action, skip it
            if not str_action.strip():
                continue

            assert " " not in str_action.strip(), "Strategy includes a space - malformed!"

            # Get rid of hanging whitespace from the splitting
            str_action = str_action.strip()

            # ActionTree uses the last "|" as a sanity check for well-formed
            # strategies, so restore the "|" that was lost from the split
            str_action = str_action + "|"
            new_tree = actions.tree.ActionTree(direction)
            new_tree.parse(str_action, logger)

            # Once all the actions are parsed, add this tree to the
            # current direction of actions
            if out:
                strat.out_actions.append(new_tree)
            else:
                strat.in_actions.append(new_tree)
        # Change the flag to tell it to parse the IN direction during the next loop iteration
        out = False
        direction = "in"
    return strat


def get_logger(basepath, log_dir, logger_name, log_name, environment_id, log_level=logging.DEBUG, demo_mode=False):
    """
    Configures and returns a logger.
    """
    if type(log_level) == str:
        log_level = log_level.upper()
    global CONSOLE_LOG_LEVEL
    full_path = os.path.join(basepath, log_dir, "logs")
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    flag_path = os.path.join(basepath, log_dir, "flags")
    if not os.path.exists(flag_path):
        os.makedirs(flag_path)
    # Set up a client logger
    logger = logging.getLogger(logger_name + environment_id)
    logger.setLevel(logging.DEBUG)
    # Disable the root logger to avoid double printing
    logger.propagate = False

    # If we've already setup the handlers for this logger, just return it
    if logger.handlers:
        return logger
    fh = logging.FileHandler(os.path.join(basepath, log_dir, "logs", "%s.%s.log" % (environment_id, log_name)))
    fh.setLevel(logging.DEBUG)

    log_prefix = "[%s] " % log_name.upper()
    formatter = logging.Formatter("%(asctime)s %(levelname)s:" + log_prefix + "%(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_formatter = logging.Formatter(log_prefix + "%(asctime)s %(message)s")
    fh.setFormatter(file_formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(log_level)
    CONSOLE_LOG_LEVEL = ch.level
    logger.addHandler(ch)
    return CustomAdapter(logger, {}) if demo_mode else logger

class CustomAdapter(logging.LoggerAdapter):
    """
    Used for demo mode, to change sensitive IP addresses where necessary. Can be used (mostly) like a regular logger.
    """
    regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    def __init__(self, logger, extras):
        super().__init__(logger, extras)
        self.handlers = logger.handlers
        self.ips = {}
    
    def debug(self, msg, *args, **kwargs):
        """
        Print a debug message, uses logger.debug.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """
        Print an info message, uses logger.info.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """
        Print a warning message, uses logger.warning.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """
        Print an error message, uses logger.error.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """
        Print a critical message, uses logger.critical.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.critical(msg, *args, **kwargs)

    def get_ip(self, ip):
        """
        Lookup the assigned random IP for a given real IP.
        If no random IP exists, a new one is created and a message is logged indicating it.
        """
        if ip not in self.ips:
            random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
            self.logger.info("Registering new random IP: %s" % random_ip)
            self.ips[ip] = random_ip

    def process(self, msg, args, kwargs):
        """
        Modify the log message to replace any instance of an IP in msg or args with its assigned random IP.
        """
        new_args = []
        for arg in args:
            if type(arg) == str:
                for ip in self.regex.findall(arg):
                    new_ip = self.get_ip(ip)

                    arg = arg.replace(ip, self.ips[ip])
            
            new_args.append(arg)

        for ip in self.regex.findall(msg):
            if ip not in self.ips:
                random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                self.logger.debug("Registering new random IP: %s" % random_ip)
                self.ips[ip] = random_ip
            new_ip = self.get_ip(ip)

            msg = msg.replace(ip, self.ips[ip])
        
        return msg, kwargs
        return msg, tuple(new_args), kwargs

def close_logger(logger):
    """
    Closes open file handles for a given logger.
    """
    # Close the file handles so we don't hold a ton of file descriptors open
    handlers = logger.handlers[:]
    for handler in handlers:
        if isinstance(handler, logging.FileHandler):
            handler.close()


def get_console_log_level():
    """
    returns log level of console handler
    """
    return CONSOLE_LOG_LEVEL


def string_to_protocol(protocol):
    """
    Converts string representations of scapy protocol objects to
    their actual objects. For example, "TCP" to the scapy TCP object.
    """
    if protocol.upper() == "TCP":
        return TCP
    elif protocol.upper() == "IP":
        return IP
    elif protocol.upper() == "UDP":
        return UDP


def get_id():
    """
    Returns a random ID
    """
    return ''.join([random.choice(string.ascii_lowercase + string.digits) for k in range(8)])


def setup_dirs(output_dir):
    """
    Sets up Geneva folder structure.
    """
    ga_log_dir = os.path.join(output_dir, "logs")
    ga_flags_dir = os.path.join(output_dir, "flags")
    ga_packets_dir = os.path.join(output_dir, "packets")
    ga_generations_dir = os.path.join(output_dir, "generations")
    ga_data_dir = os.path.join(output_dir, "data")
    for directory in [ga_log_dir, ga_flags_dir, ga_packets_dir, ga_generations_dir, ga_data_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
    return ga_log_dir


def get_interface():
    """
    Chooses an interface on the machine to use for socket testing.
    """
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        if "lo" in iface:
            continue
        info = netifaces.ifaddresses(iface)
        # Filter for IPv4 addresses
        if netifaces.AF_INET in info:
            return iface
