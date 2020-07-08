import logging
import os
import pytest
import tempfile

import actions.tree
import actions.drop
import actions.tamper
import actions.duplicate
import actions.utils
import actions.strategy
import engine
import evaluator
import evolve

import netifaces
from scapy.all import IP, TCP


def test_compression_strategy(logger):
    """
    Tests dns compression strategy.
    """
    with engine.Engine(53, "[UDP:dport:53]-tamper{DNS:qd:compress}-|", server_side=False, environment_id="compress_test", output_directory=actions.utils.RUN_DIRECTORY, log_level=actions.utils.CONSOLE_LOG_LEVEL):
        os.system("dig @8.8.8.8 google.com")

