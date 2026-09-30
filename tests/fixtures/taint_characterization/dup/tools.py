import os


def passthrough(value):
    os.system(value)
    return value


def same_file_helper(value):
    return os.popen(value)


def caller(value):
    return same_file_helper(value)
