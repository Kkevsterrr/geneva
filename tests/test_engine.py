import os
import sys

# Add the path to the engine so we can import it
BASEPATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASEPATH)

import engine

def test_engine():
    """
    Basic engine test
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl http://example.com?q=ultrasurf")


def test_engine_sleep():
    """
    Basic engine test with sleep action
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:S]-sleep{1}-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="info") as eng:
        os.system("curl http://example.com?q=ultrasurf")

    # Strategy to use in opposite direction
    strategy = "\/ [TCP:flags:SA]-sleep{1}-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl http://example.com?q=ultrasurf")



def test_engine_trace():
    """
    Basic engine test with trace
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "[TCP:flags:PA]-trace{2:10}-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl -m 5 http://example.com?q=ultrasurf")


def test_engine_drop():
    """
    Basic engine test with drop
    """
    # Port to run the engine on
    port = 80
    # Strategy to use
    strategy = "\/ [TCP:flags:SA]-drop-|"

    # Create the engine in debug mode
    with engine.Engine(port, strategy, log_level="debug") as eng:
        os.system("curl -m 3 http://example.com?q=ultrasurf")

