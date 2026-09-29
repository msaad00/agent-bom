import re

ALLOWED = {"alpha", "beta"}


def is_allowed(value):
    if value in ALLOWED:
        return True
    else:
        return False


def check_name(name):
    if not re.fullmatch(r"[a-z]+", name):
        return False
    return True


def verify_token(token, other):
    return validate_inner(token)


def validate_inner(token):
    if token.startswith("ok"):
        return True
    return False


def looping_guard(a):
    return looping_guard_two(a)


def looping_guard_two(a):
    return looping_guard(a)


def safe_kw(value, mode="strict"):
    return check_name(name=value)


def plain_helper(value):
    return value.strip()
