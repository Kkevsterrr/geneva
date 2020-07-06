"""
Geneva superclass object for defining a packet-level action.
"""

import inspect
import importlib
import os
import sys

import actions.utils


ACTION_CACHE = {}
ACTION_CACHE["in"] = {}
ACTION_CACHE["out"] = {}
BASEPATH = os.path.sep.join(os.path.dirname(os.path.abspath(__file__)).split(os.path.sep)[:-1])


class Action():
    """
    Defines the superclass for a Geneva Action.
    """
    # Give each Action a unique ID - this is needed for graphing/visualization
    ident = 0
    # Each Action has a 'frequency' field - this defines how likely it is to be chosen
    # when a new action is chosen
    frequency = 0

    def __init__(self, action_name, direction):
        """
        Initializes this action object.

        Args:
            action_name (str): Name of this action ("duplicate")
            direction (str): Direction of this action ("out", "both", "in")
        """
        self.enabled = True
        self.action_name = action_name
        self.direction = direction
        self.requires_undo = False
        self.num_seen = 0

        self.left = None
        self.right = None
        self.branching = False
        self.terminal = False
        self.ident = Action.ident
        Action.ident += 1

    def applies(self, direction):
        """
        Returns whether this action applies to the given direction, as
        branching actions are not supported on inbound trees.

        Args:
            direction (str): Direction to check if this action applies ("out", "in", "both")

        Returns:
            bool: whether or not this action can be used to a given direction
        """
        if direction == self.direction or self.direction == "both":
            return True
        return False

    def mutate(self, environment_id=None):
        """
        Mutates packet.
        """

    def __str__(self):
        """
        Defines string representation of this action.
        """
        return "%s" % (self.action_name)

    @staticmethod
    def get_actions(direction, disabled=None, allow_terminal=True):
        """
        Dynamically imports all of the Action classes in this directory.

        Will only return terminal actions if terminal is set to True.

        Args:
            direction (str): Limit imported actions to just those that can run to this direction ("out", "in", "both")
            disabled (list, optional): list of actions that are disabled
            allow_terminal (bool): whether or not terminal actions ("drop") should be imported

        Returns:
            dict: Dictionary of imported actions
        """
        if disabled is None:
            disabled = []
        # Recursively call this function again to enumerate in and out actions
        if direction.lower() == "both":
            return list(set(Action.get_actions("in", disabled=disabled, allow_terminal=allow_terminal) + \
                            Action.get_actions("out", disabled=disabled, allow_terminal=allow_terminal)))

        terminal = "terminal"
        if not allow_terminal:
            terminal = "non-terminal"

        if terminal not in ACTION_CACHE[direction]:
            ACTION_CACHE[direction][terminal] = {}
        else:
            return ACTION_CACHE[direction][terminal]

        collected_actions = []
        # Get the base path for the project relative to this file
        path = os.path.join(BASEPATH, "actions")
        for action_file in os.listdir(path):
            if not action_file.endswith(".py"):
                continue
            action = action_file.replace(".py", "")
            if BASEPATH not in sys.path:
                sys.path.append(BASEPATH)

            importlib.import_module("actions." + action)
            def check_action(obj):
                return inspect.isclass(obj) and \
                        issubclass(obj, actions.action.Action) and \
                        obj != actions.action.Action and \
                        obj().applies(direction) and \
                        obj().enabled and \
                        not any([x in str(obj) for x in disabled]) and \
                        (allow_terminal or not obj().terminal)
            clsmembers = inspect.getmembers(sys.modules["actions."+action], predicate=check_action)
            collected_actions += clsmembers

        collected_actions = list(set(collected_actions))

        ACTION_CACHE[direction][terminal] = collected_actions

        return collected_actions

    @staticmethod
    def parse_action(str_action, direction, logger):
        """
        Parses a string action into the action object.

        Args:
            str_action (str): String representation of an action to parse
            direction (str): Limit actions searched through to just those that can run to this direction ("out", "in", "both")
            logger (:obj:`logging.Logger`): a logger to log with

        Returns:
            :obj:`action.Action`: A parsed action object
        """
        # Collect all viable actions that can run for each respective direction
        outs = Action.get_actions("out")
        ins = Action.get_actions("in")

        # If we're currently parsing the OUT forest, only search the out-compatible actions
        if direction == "out":
            search = outs
        # Otherwise only search in-compatible actions (no branching)
        else:
            search = ins

        action_obj = None
        data = None
        # If this action has parameters (defined within {} attached to the action),
        # split off the data parameters from the raw action name
        if "{" in str_action:
            str_action, data = str_action.split("{")
            data = data.replace("}", "")

        # Search through all of the actions available for this direction to find the right class
        for action_name, action_cls in search:
            if str_action.strip() and str_action.lower() in action_name.lower():
                # Define the action, and give it a reference to its parent strategy
                action_obj = action_cls()
                # If this action has data, ask the new module to parse & initialize itself to it
                if data:
                    # Pass our logger to the action to alert us if it can't parse something
                    action_obj.parse(data, logger)
        return action_obj
