from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import random
import csv

class swxmlclass():
    def __init__(self):
        self.name=None
        self._isipempty=True
        self.id=str(random.randint(1,60000))
        self.host_baseline_enable="true"
        self.supress_excluded_service="true"
        self.inverse_suppression="false"
        self.host_trap="false"
        self.sendtocta="false"
        self.ip_address_range=None
        self.main_group=None
        self.parent_group_1=None
        self.parent_group_2=None
        self.parent_group_3=None
        self.parent_group_4=None
        self._isnew=True
        self._isgroupempty1=False
        self._isgroupempty2=False
        self._isgroupempty3=False
        self._isgroupempty4=False
        self._hasbeenadded=False



