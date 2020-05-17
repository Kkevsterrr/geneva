"""
Miscellaneous tests for plugins & related functionality
"""
import copy
import sys
import requests
import os
import pytest

# Many sites inside the external pool do not let multiple requests from travis,
# making the test frequently have false negative failures.
@pytest.mark.skip()
def test_testserver(logger):
    """
    Tests the TestServer class
    """
    path = os.path.join("plugins", "http")
    if path not in sys.path:
        sys.path.append(path)
    from plugins.http.plugin import TestServer
    for _ in range(10):
        site = None
        with TestServer(site, None, {}, logger) as site:
            logger.info("Got site: %s" % site)
            req = requests.get(site, timeout=10)
            req.raise_for_status()
            logger.info("Success")

    import plugins.http.plugin
    orig = plugins.http.plugin.TEST_SITES
    try:
        # Overwrite the test sites with a failure case and a success case
        plugins.http.plugin.TEST_SITES = ["http://nononono.no", "http://example.com"]
        plugins.http.plugin.JAIL_TRACKER = {}
        for site in plugins.http.plugin.TEST_SITES:
            plugins.http.plugin.JAIL_TRACKER[site] = 0

        site = None
        with TestServer(site, None, {}, logger) as site:
            assert site != "http://nononono.no"
            logger.info("Got site: %s" % site)
            req = requests.get(site, timeout=10)
            req.raise_for_status()
            logger.info("Success")
    finally:
        plugins.http.plugin.TEST_SITES = copy.deepcopy(orig)
        plugins.http.plugin.JAIL_TRACKER = {}
        for site in plugins.http.plugin.TEST_SITES:
            plugins.http.plugin.JAIL_TRACKER[site] = 0



