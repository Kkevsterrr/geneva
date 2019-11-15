import os
import sys

# Add the path to the engine so we can import it
BASEPATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASEPATH)

import engine

# Port to run the engine on
port = 80
# Strategy to use
strategy = "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/"

# Create the engine in debug mode
with engine.Engine(port, strategy, log_level="debug") as eng:
    os.system("curl http://example.com?q=ultrasurf")
