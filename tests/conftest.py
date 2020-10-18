import json
import pytest
import logging
import subprocess
import tempfile
import os
import shutil

import evolve
import layers.packet


def pytest_addoption(parser):
    """
    Adds options to pytest
    """
    parser.addoption(
        "--evolve-logger", action="store", choices=("debug", "info", "warning", "critical", "error"), help="Sets the log level", default="info"
        )


@pytest.fixture(scope="session")
def logger(request):
    """
    Returns log level requested.
    """
    # On some systems, docker and urllib3 log levels are cleared (such as Travis)
    # Reset them to warnings only to keep logging sane.
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    level = request.config.getoption("--evolve-logger")
    logger = evolve.setup_logger(level)
    return logger


@pytest.fixture(autouse=True, scope="function")
def reset_packet_restrictions():
    """
    Autouse feature to make sure tests have a clean slate for processing.
    """
    layers.packet.Packet.reset_restrictions()


@pytest.mark.tryfirst
@pytest.fixture(autouse=True, scope="function")
def blank_new_line():
    """
    Autouse feature to print a new line after the test name for cleaner printing.
    """
    print("")


@pytest.fixture
def client_worker(request):
    """
    Defines a client worker fixture. This creates a docker container
    with SSH enabled and the code mounted to test the evaluator's client workers.
    """
    container = {}
    worker_path = tempfile.mkdtemp()
    os.makedirs(os.path.join(worker_path, "test_container"))
    info_path = os.path.join(worker_path, "worker.json")
    worker_dict = {
        "ip" : "127.0.0.1",
        "hostname" : "",
        "port" : 2222,
        "username" : "root",
        "password" : "Docker!",
        "geneva_path" : "/code",
        "python" : "python3"
    }

    with open(info_path, "w") as fd:
        json.dump(worker_dict, fd)
    container["worker"] = info_path

    def fin(cid):
        shutil.rmtree(worker_path)
        if cid:
            print("\nCleaning up container")
            subprocess.check_call(["docker", "stop", cid])

    cid = None
    # Run the base docker container to give us a worker client
    cid = subprocess.check_output(["docker", "run", "--privileged", "--dns=8.8.8.8", "-id", "-p", "2222:22", "-v", "%s:/code" % os.path.abspath(os.getcwd()), "base"]).decode("utf-8").strip()
    request.addfinalizer(lambda: fin(cid))
    print("\nCreated container %s" % cid[:8])
    container["id"] = cid
    container["cid"] = cid[:8]

    #output = subprocess.check_output(["docker", "exec", "-i", cid, "ifconfig", "eth0"])

    #ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', output.decode("utf-8"))[0]
    #print("Parsed container ip: %s" % ip)
    container["ip"] = "0.0.0.0"

    subprocess.check_call(["docker", "exec", "-i", cid, "service", "ssh", "start"])
    return container
