from lxml import etree


def parse(body):
    return etree.fromstring(body)
