#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hmac
import hashlib
import inspect
import os
import sys
import re
import random
import requests
from enum import Enum
from string import printable

""" <config> """
# SERVICE INFO
PORT = 8080

# DEBUG -- logs to stderr, TRACE -- verbose log
DEBUG = os.getenv("DEBUG", False)
TRACE = os.getenv("TRACE", False)

#regs for a flag
FLAG_RE = re.compile("[A-Z0-9]{31}=")
FLAG_ID = re.compile("[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")

#bad option with secret
SECRET = b"pQw>1=yj%Ln'j=.Jc+KUH$WA_@B%/dW$6kctkjp}"
""" </config> """

def check_login_register(host):
    name = generate_random(printable, 20)
    p = generate_pswd(name)
    data = {"username": name, "password": p}

    session = requests.Session()    

    session.post(f"http://{host}:{PORT}/signup", data = data)

    session.post(f"http://{host}:{PORT}/auth", data = data)

    t = session.get(f"http://{host}:{PORT}/bar")

    session.post(f"http://{host}:{PORT}/logout")

    if "Honey Bar" in t.text:
        return True
    return False


def check_double_register(host):
    name = generate_random(printable, 20)
    p = generate_pswd(name)
    data = {"username": name, "password": p}

    session = requests.Session()    

    session.post(f"http://{host}:{PORT}/signup", data = data)

    session.post(f"http://{host}:{PORT}/auth", data = data)

    t = session.get(f"http://{host}:{PORT}/bar")
    
    if "Honey Bar" not in t.text:
        return True

    session.post(f"http://{host}:{PORT}/logout")

    p_new = generate_random(printable, 5)
    data = {"username": name, "password": p_new}

    session.post(f"http://{host}:{PORT}/signup", data = data)

    session.post(f"http://{host}:{PORT}/auth", data = data)

    t = session.get(f"http://{host}:{PORT}/bar")

    session.post(f"http://{host}:{PORT}/logout")

    if "Honey Bar" not in t.text:
        return True
    return False


def check_list_of_users(host):
    name = generate_random(printable, 20)
    p = generate_pswd(name)
    data = {"username": name, "password": p}

    session = requests.Session()    

    session.post(f"http://{host}:{PORT}/signup", data = data)

    session.post(f"http://{host}:{PORT}/auth", data = data)

    session.post(f"http://{host}:{PORT}/logout")

    second_one = generate_random(printable, 20)
    p = generate_pswd(second_one)
    data = {"username": second_one, "password": p}

    session.post(f"http://{host}:{PORT}/signup", data = data)

    session.post(f"http://{host}:{PORT}/auth", data = data)

    t = session.get(f"http://{host}:{PORT}/bar")

    session.post(f"http://{host}:{PORT}/logout")

    if name in t.text and second_one in t.text:
        return True
    return False


def check(host):
    try:
        if not check_login_register(host):
            die(ExitStatus.MUMBLE, "Bar wasn't achived")

        if not check_list_of_users(host):
            die(ExitStatus.MUMBLE, "List of users was hidden")

        if not check_double_register(host):
            die(ExitStatus.MUMBLE, "Reregistration is possible")

        die(ExitStatus.OK, "Everything was OK")
    except Exception:
        die(ExitStatus.DOWN, "Exception was recieved")


def generate_random(alph, length):
    return ''.join(random.choice(alph) for i in range(length))


def generate_pswd(flag_id):
    h = hmac.new(key = SECRET, msg = flag_id.encode(), digestmod=hashlib.sha256)
    return h.hexdigest()
    

def put(host, flag_id, flag, vuln):
    try: 
        p = generate_pswd(flag_id)
        data = {"username": flag_id, "password": p}

        session = requests.Session()
        session.post(f"http://{host}:{PORT}/signup", data = data)

        session.post(f"http://{host}:{PORT}/auth", data = data)

        session.post(f"http://{host}:{PORT}/addRecipe", {"recipe": flag})

        die(ExitStatus.OK, "Ok")
    except Exception:
        die(ExitStatus.DOWN, "Exception recieved")


def get(host, flag_id, flag, vuln):
    try: 
        p = generate_pswd(flag_id)
        data = {"username": flag_id, "password": p}

        session = requests.Session()
        session.post(f"http://{host}:{PORT}/signup", data = data)

        session.post(f"http://{host}:{PORT}/auth", data = data)

        t = session.get(f"http://{host}:{PORT}/recipes").text
        
        if flag in t:
            die(ExitStatus.OK, "Flag was found")
        else:
            die(ExitStatus.CORRUPT, "Flag wasn't found")
    except Exception:
        die(ExitStatus.DOWN, "Exception recieved")


""" <common> """


class ExitStatus(Enum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110


def _log(obj):
    if DEBUG and obj:
        caller = inspect.stack()[1].function
        print(f"[{caller}] {obj}", file=sys.stderr, flush=True)
    return obj


def die(code: ExitStatus, msg: str):
    if msg:
        print(msg, file=sys.stderr, flush=True)
    exit(code.value)


def _main():
    action, *args = sys.argv[1:]

    try:
        if action == "check":
            host, = args
            check(host)
        elif action == "put":
            host, flag_id, flag, vuln = args
            put(host, flag_id, flag, vuln)
        elif action == "get":
            host, flag_id, flag, vuln = args
            get(host, flag_id, flag, vuln)
        else:
            raise IndexError
    except ValueError:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Usage: {sys.argv[0]} check|put|get IP FLAGID FLAG",
        )
    except Exception as e:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Exception: {e}. Stack:\n {inspect.stack()}",
        )


""" </common> """

if __name__ == "__main__":
    _main()
