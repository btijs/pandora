import inspect
import json
import logging

import IPython

from ui.log_setup import console

import IPython

from ui.log_setup import console


def file_stream_is_elf_file(stream):
    """
    Checks whether a file stream currently has a legit elf file open.
    Verifies that the ELF HEADER exists.
    """
    stream.seek(0)
    elf_magic = stream.read(4)
    stream.seek(0)
    if elf_magic == b"\x7fELF":
        return True
    else:
        return False


def decode_as_json(json_path):
    """
    Takes a path to a json file and returns an object loaded by the json library.
    """
    logger = logging.getLogger()

    with open(json_path, "r") as f:
        try:
            json_dict = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Json Decode error on file {json_path}:\n{str(e)}")
            exit(1)
    return json_dict


def hexify(obj):
    if isinstance(obj, int):
        return hex(obj)
    elif isinstance(obj, (list, tuple, set)):
        t = type(obj)
        return t(hexify(x) for x in obj)
    elif isinstance(obj, dict):
        return {hexify(k): hexify(v) for k, v in obj.items()}
    else:
        return obj


def auto_embed(*args, **kwargs):
    """
    This is a helper function to automatically embed an IPython shell, while making sure that
      - the caller's local variables are available in the IPython shell, so that the user can interact with them.
      - any live displays are properly stopped and restarted to avoid issues with the display.
    """

    # Copy the live stack, because they will get cleared when we stop them, and we want to restart them after embedding.
    lives = console._live_stack.copy()
    [lv.stop() for lv in lives]

    # Get the caller's frame to pass to IPython, so that the user has access to the local variables of the caller.
    frame = inspect.currentframe().f_back
    try:
        IPython.embed(
            user_ns=dict(frame.f_locals),
            global_ns=dict(frame.f_globals),
            *args,
            **kwargs,
        )
    finally:
        [lv.start() for lv in lives]
