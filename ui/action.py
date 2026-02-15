import logging
from enum import Enum
from inspect import getmembers, isfunction

import typer

import pandora_options
from ui.log_format import format_fields, format_header, format_inline_header, log_always
from utilities.helper import auto_embed

logger = logging.getLogger(__name__)


class UserAction(str, Enum):
    EXIT = "exit"
    SHELL = "shell"
    BREAK = "break"
    NONE = "none"

    @staticmethod
    def get_action_names():
        return [v.value for v in UserAction.__members__.values()]

    @staticmethod
    def get_action_help():
        rv = {}
        for act in UserAction.__members__.values():
            rv[act.value] = act.get_help_text()
        return rv

    def get_help_text(self):
        if self.value == "exit":
            return "Terminates the program."
        elif self.value == "shell":
            return "Spawns an interactive shell."
        elif self.value == "break":
            return "Stops and waits for user input before proceeding."
        elif self.value == "none":
            return "Do nothing (default)."


class UserActionWithLevel:
    def __init__(self, level: int = 0, user_action: UserAction = UserAction.NONE) -> None:
        self.level = level
        self.user_action = user_action
        self.only_unique = False

    def __call__(self, *args, **kwargs):
        """
        Calls the UserAction, passing named optional arguments:
            'state'     -- for use in interactive shell
            'unique'    -- for limiting actions on duplicates
            'info'      -- for indicating reason for action in log
            'level'     -- for indicating log level of reason in log
        """
        state = kwargs.get("state", None)
        unique = kwargs.get("unique", True)
        info = format_header(kwargs.get("info", ""))
        level = kwargs.get("level", None)

        def abort_execution():
            log_always(logger, "User requested to abort. The current step will still be completed which may trigger another shell or two.")
            pandora_options.PANDORA_USER_REQUESTED_EXIT = True

        if self.only_unique and not unique:
            return

        if self.user_action.value == "none":
            return

        elif level and self.level and level < self.level:
            # Check level only after checking action is not NONE, for performance reasons.
            logger.debug(f"Skipping action {self.user_action.value} because level {level} is below required level {self.level}")
            return

        elif self.user_action.value == "exit":
            logger.critical(f"{info} Exiting..")
            exit()

        elif self.user_action.value == "shell":
            log_always(logger, f"{info} Spawning interactive Python shell:")
            if state:
                # log_always seems to have issues logging dicts right now, so use logger.critical here.
                logger.critical(f"You have access to the {format_header('state')} variable to access angr:\n{format_fields(state)}")
            import utilities.angr_helper

            log_always(logger, f"You have access to these utilities.angr_helper convenience functions:\n {format_fields([o[0] for o in getmembers(utilities.angr_helper) if isfunction(o[1])])}")
            import explorer.enclave

            log_always(logger, f"You have access to these explorer.enclave convenience functions:\n {format_fields([o[0] for o in getmembers(explorer.enclave) if isfunction(o[1])])}")
            log_always(logger, f"Use the local function {format_inline_header('abort_execution')} to exit Pandora.")

            auto_embed()

        elif self.user_action.value == "break":
            logger.critical(f"{info} Breaking. Press any key to continue..")
            input()

        if not self.only_unique and not unique:
            self.only_unique = typer.confirm(f"Do you want to only {self.user_action.value} on unique symbols?")
