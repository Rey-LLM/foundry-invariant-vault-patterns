from lxml import etree

PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


def parse(body):
    return etree.fromstring(body, PARSER)
