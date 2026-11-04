import requests


def get(u):
    return requests.get(u, verify=False, timeout=5)
