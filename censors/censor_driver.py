import argparse
import importlib
import inspect
import os
import traceback
import sys

BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASEPATH)

if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

import censors.censor

CENSORS = {}

def get_censors():
    """
    Dynamically imports all of the Censors classes in this directory.
    """
    global CENSORS
    if CENSORS:
        return CENSORS

    collected_censors = {}
    for censor_file in os.listdir(os.path.dirname(os.path.abspath(__file__))):
        if not censor_file.endswith(".py"):
            continue
        censor_file = censor_file.replace(".py", "")
        importlib.import_module("censors."+censor_file)
        def check_censor(o):
            return inspect.isclass(o) and issubclass(o, censors.censor.Censor) and o != censors.censor.Censor
        clsmembers = inspect.getmembers(sys.modules["censors."+censor_file], predicate=check_censor)
        if clsmembers:
            name, censor_class = clsmembers[0]
            if censor_class(0, [], None, None, None, None).enabled:
                collected_censors[name.lower()] = censor_class

    CENSORS = collected_censors
    return collected_censors


def get_args():
    """
    Sets up argparse and collects arguments.
    """
    parser = argparse.ArgumentParser(description='The server, run by the evaluator.')
    parser.add_argument('--port', type=int, action='store', help="Server port",
                        required=True)
    parser.add_argument('--queue', type=int, action='store', help="NFQueue number to use",
                        required=True)
    parser.add_argument('--environment-id', action='store', help="ID of the current environment",
                        required=True)
    parser.add_argument('--censor', action='store', help="censor to deploy", required=True)
    parser.add_argument('--forbidden', action='store', default='ultrasurf', help="word to censor")
    parser.add_argument('--output-directory', action='store', help="Where to write logs",
                        required=True)
    parser.add_argument('--log', action='store', default="debug",
                        choices=("debug", "info", "warning", "critical", "error"),
                        help="Sets the log level")

    return parser.parse_args()


def main(args):
    """
    Starts the given censor.
    """
    try:
        censors = get_censors()
        censor_name = args["censor"].lower()

        if censor_name not in censors:
            print("ERROR: Unknown censor.")
            return None
        censor_cls = censors[censor_name]
        censor = censor_cls(args["environment_id"],
                            [args["forbidden"].encode('utf-8')],
                            args["output_directory"],
                            args["log"],
                            args["port"],
                            args["queue"])
        print("Censor %s starting." % censor_name)
        censor.start()
    except Exception as e:
        print(e)
        traceback.print_exc()


# Note that this code can be removed - this is how the
# evaluator runs the censor for tests in the Docker environment
if __name__ == "__main__":
    main(vars(get_args()))
