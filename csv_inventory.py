import csv
from swxmlclass import swxmlclass
from xml.etree.ElementTree import Element, SubElement, Comment, tostring, fromstring, parse
import xml.dom.minidom
import random
from operator import itemgetter
import collections
import operator


def csv_to_dic(filename):
    inventory_dic_list=[]


    with open(filename, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file,delimiter=";")
        sortedlist = sorted(csv_reader, key=lambda row:(row['Parent_Group 1'],row['Parent_Group 2'],row['Parent_Group 3'], row['Parent_Group 4']))

    with open('sorted.csv','w') as f:
        fieldnames = ['IP_Range','Enable_Baselining','Send_to_CTA','Disable_Security_Events_for_Excluded_Services','Main_Group','Parent_Group 1','Parent_Group 2','Parent_Group 3','Parent_Group 4']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in sortedlist:
            writer.writerow(row)

    with open('sorted.csv',mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=",")
        for row in csv_reader:
            inventory_dic_list.append(row)
    return inventory_dic_list



def create_outside(ogfile):
    tree = parse(ogfile)
    root = tree.getroot()
    sub_outside = root.find('outside-hosts')

    return sub_outside



def create_inside(root):
    sub_inside = SubElement(root, 'inside-hosts',
                          {'host-baselines': "true", 'suppress-excluded-services': "true",
                           'inverse-suppression': "false",
                           'host-trap': "false"})
    return sub_inside



if __name__ == '__main__':

    inventory_dic_list = csv_to_dic('Stealthwatch_HG_Template.csv')

    root = Element('host-group-tree')
    sub_inside = create_inside(root)


    catch_all = SubElement(sub_inside, 'host-group', {'id': str(random.randint(1, 60000)), 'name': 'Catch All',
                                                         'host-baselines': "true",
                                                         'suppress-excluded-services': "true",
                                                         'inverse-suppression': "false",
                                                         'host-trap': "false",
                                                         'send-to-cta': "false"})

    ip1 = SubElement(catch_all, 'ip-address-ranges')
    ip1.text = '10.0.0.0/8'
    ip2 = SubElement(catch_all, 'ip-address-ranges')
    ip2.text = '192.168.0.0/16'
    ip3 = SubElement(catch_all, 'ip-address-ranges')
    ip3.text = '172.16.0.0/20'

    by_function = SubElement(sub_inside, 'host-group', {'id': str(random.randint(1, 60000)), 'name': 'By Function',
                                                         'host-baselines': 'true',
                                                         'suppress-excluded-services': 'false',
                                                         'inverse-suppression': "false",
                                                         'host-trap': "false",
                                                         'send-to-cta': 'false'})

    by_location = SubElement(sub_inside, 'host-group', {'id': str(random.randint(1, 60000)), 'name': 'By Location',
                                                         'host-baselines': 'true',
                                                         'suppress-excluded-services': 'false',
                                                         'inverse-suppression': "false",
                                                         'host-trap': "false",
                                                         'send-to-cta': 'false'})





    for items in inventory_dic_list:

        a = swxmlclass()
        a.ip_address_range=items['IP_Range']
        a._isipempty=True
        a.id=str(random.randint(1,60000))
        a.host_baseline_enable=items['Enable_Baselining'].lower()
        a.supress_excluded_service=items['Disable_Security_Events_for_Excluded_Services'].lower()
        a.inverse_suppression="false"
        a.host_trap="false"
        a.sendtocta=items['Send_to_CTA'].lower()
        a.ip_address_range=items['IP_Range']
        a.main_group=items['Main_Group']
        a.parent_group_1=items['Parent_Group 1']
        a.parent_group_2=items['Parent_Group 2']
        a.parent_group_3=items['Parent_Group 3']
        a.parent_group_4=items['Parent_Group 4']


        # Exist Flags
        pg4=False
        pg3=False
        pg2=False
        pg1=False
        # Is Empty Flags

        if a.parent_group_1 == '':
            a._isgroupempty1 = True
        if a.parent_group_2 == '':
            a._isgroupempty2 = True
        if a.parent_group_3 == '':
            a._isgroupempty3 = True
        if a.parent_group_4 == '':
            a._isgroupempty4 = True

        for xml1 in root.iter():
            for x1 in xml1.findall('host-group'):
                if a.parent_group_1 == x1.get('name'):
                    pg1 = True
                    tempx1 = x1
                    break
            else:
                continue
            break

        for xml2 in root.iter():
            for x2 in xml2.findall('host-group'):
                if a.parent_group_2 == x2.get('name'):
                    pg2 = True
                    tempx2 = x2
                    break
            else:
                continue
            break

        for xml3 in root.iter():
            for x3 in xml3.findall('host-group'):
                if a.parent_group_3 == x3.get('name'):
                    pg3 = True
                    tempx3 = x3
                    break
            else:
                continue
            break

        for xml4 in root.iter():
            for x4 in xml4.findall('host-group'):
                if a.parent_group_4 == x4.get('name'):
                    pg4 = True
                    tempx4 = x4
                    break
            else:
                continue
            break

        # Conditional Add

        if a._hasbeenadded == False:
            if pg1 == True and pg2 == True and pg3 == True and pg4 == True:
                if a.ip_address_range != '':
                    ip = SubElement(tempx4, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == True and pg2 == True and pg3 == True and a._isgroupempty4 == True:
                if a.ip_address_range !='':
                    ip = SubElement(tempx3, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == True and pg2 == True and a._isgroupempty3 == True and a._isgroupempty4 == True:
                if a.ip_address_range !='':
                    ip = SubElement(tempx2, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == True and a._isgroupempty2 == True and a._isgroupempty3 == True and a._isgroupempty4 == True:
                if a.ip_address_range !='':
                    ip = SubElement(tempx1, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True

        if a._hasbeenadded == False:
            if a._isgroupempty1 == True and a._isgroupempty2 == True and a._isgroupempty3 == True and a._isgroupempty4 == True:
                if a.main_group == 'By Location':
                    if a.ip_address_range != '':
                        ip = SubElement(by_location, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True
                if a.main_group == 'By Function':
                    if a.ip_address_range != '':
                        ip = SubElement(by_function, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True


        if a._hasbeenadded == False:
            if pg1 == False and pg2 == False and pg3 == False and pg4 == False and a._isgroupempty1 == False and a._isgroupempty2 == False and a._isgroupempty3 == False and a._isgroupempty4 == False:
                if a.main_group == 'By Location':
                    new_element_1 = SubElement(by_location, 'host-group',
                                            {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})
                    new_element_2 = SubElement(new_element_1, 'host-group',
                                            {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})

                    new_element_3 = SubElement(new_element_2, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_4 = SubElement(new_element_3, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_4,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element_4, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True
                if a.main_group == 'By Function':
                    new_element_1 = SubElement(by_function, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_2 = SubElement(new_element_1, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})

                    new_element_3 = SubElement(new_element_2, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_4 = SubElement(new_element_3, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_4,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True

                    if a.ip_address_range != '':
                        ip = SubElement(new_element_4, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == False and pg2 == False and pg3 == False and a._isgroupempty1 == False and a._isgroupempty2 == False and a._isgroupempty3 == False:
                if a.main_group == 'By Location':
                    new_element_1 = SubElement(by_location, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_2 = SubElement(new_element_1, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})

                    new_element_3 = SubElement(new_element_2, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':

                        ip = SubElement(new_element_3, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True
                if a.main_group == 'By Function':
                    new_element_1 = SubElement(by_function, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_2 = SubElement(new_element_1, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})

                    new_element_3 = SubElement(new_element_2, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element_3, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == False and pg2 == False and a._isgroupempty1 == False and a._isgroupempty2 == False:
                if a.main_group == 'By Location':
                    new_element_1 = SubElement(by_location, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_2 = SubElement(new_element_1, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element_2, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True
                if a.main_group == 'By Function':
                    new_element_1 = SubElement(by_function, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    new_element_2 = SubElement(new_element_1, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element_2, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == False and a._isgroupempty1 == False:
                if a.main_group == 'By Location':
                    new_element_1 = SubElement(by_location, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element_1, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True
                if a.main_group == 'By Function':
                    new_element_1 = SubElement(by_function, 'host-group',
                                               {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                                'host-baselines': a.host_baseline_enable,
                                                'suppress-excluded-services': a.supress_excluded_service,
                                                'inverse-suppression': a.inverse_suppression,
                                                'host-trap': a.host_trap,
                                                'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element_1, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True



        if a._hasbeenadded == False:
            if pg1 == True and pg2 == True and pg3 == True and pg4 == False and a._isgroupempty1 == False and a._isgroupempty2 == False and a._isgroupempty3 == False and a._isgroupempty4 == False:
                new_element = SubElement(tempx3, 'host-group',
                                         {'id': str(random.randint(1, 60000)), 'name': a.parent_group_4,
                                          'host-baselines': a.host_baseline_enable,
                                          'suppress-excluded-services': a.supress_excluded_service,
                                          'inverse-suppression': a.inverse_suppression,
                                          'host-trap': a.host_trap,
                                          'send-to-cta': a.sendtocta})
                a._hasbeenadded = True
                if a.ip_address_range != '':
                    ip = SubElement(new_element, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == True and pg2 == False and pg3 == False and pg4 == False and a._isgroupempty2 == False and a._isgroupempty3 == False and a._isgroupempty4 == True:
                new_element_1 = SubElement(tempx1, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})
                new_element_2 = SubElement(new_element_1, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})
                a._hasbeenadded = True
                if a.ip_address_range != '':
                    ip = SubElement(new_element_2, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True


        if a._hasbeenadded == False:
            if pg1 == True and pg2 == False and pg3 == False and pg4 == False and a._isgroupempty2 == False and a._isgroupempty3 == False and a._isgroupempty4 == False:
                new_element_1 = SubElement(tempx1, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})
                new_element_2 = SubElement(new_element_1, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})

                new_element_3 = SubElement(new_element_2, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_4,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})

                a._hasbeenadded = True
                if a.ip_address_range != '':

                    ip = SubElement(new_element_3, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True


        if a._hasbeenadded == False:
            if pg1 == True and pg2 == True and pg3 == False and pg4 == False and a._isgroupempty3 == False and a._isgroupempty4 == False:
                new_element_1 = SubElement(tempx2, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})
                new_element_2 = SubElement(new_element_1, 'host-group',
                                           {'id': str(random.randint(1, 60000)), 'name': a.parent_group_4,
                                            'host-baselines': a.host_baseline_enable,
                                            'suppress-excluded-services': a.supress_excluded_service,
                                            'inverse-suppression': a.inverse_suppression,
                                            'host-trap': a.host_trap,
                                            'send-to-cta': a.sendtocta})
                a._hasbeenadded = True
                if a.ip_address_range != '':
                    ip = SubElement(new_element_2, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True


        if a._hasbeenadded == False:
            if pg1 == True and pg2 == True and pg3 == False and a._isgroupempty3 == False and a._isgroupempty4 == True:
                new_element = SubElement(tempx2, 'host-group',
                                         {'id': str(random.randint(1, 60000)), 'name': a.parent_group_3,
                                          'host-baselines': a.host_baseline_enable,
                                          'suppress-excluded-services': a.supress_excluded_service,
                                          'inverse-suppression': a.inverse_suppression,
                                          'host-trap': a.host_trap,
                                          'send-to-cta': a.sendtocta})
                a._hasbeenadded = True
                if a.ip_address_range != '':
                    ip = SubElement(new_element, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True


        if a._hasbeenadded == False:
            if pg1 == True and pg2 == False and a._isgroupempty1 == False and a._isgroupempty2 == False:
                new_element = SubElement(tempx1, 'host-group',
                                         {'id': str(random.randint(1, 60000)), 'name': a.parent_group_2,
                                          'host-baselines': a.host_baseline_enable,
                                          'suppress-excluded-services': a.supress_excluded_service,
                                          'inverse-suppression': a.inverse_suppression,
                                          'host-trap': a.host_trap,
                                          'send-to-cta': a.sendtocta})

                a._hasbeenadded = True
                if a.ip_address_range != '':
                    ip = SubElement(new_element, 'ip-address-ranges')
                    ip.text = a.ip_address_range
                    a._hasbeenadded = True

        if a._hasbeenadded == False:
            if pg1 == False and a._isgroupempty1 == True:
                if a.main_group == 'By Location':
                    new_element = SubElement(by_location, 'host-group',
                                             {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                              'host-baselines': a.host_baseline_enable,
                                              'suppress-excluded-services': a.supress_excluded_service,
                                              'inverse-suppression': a.inverse_suppression,
                                              'host-trap': a.host_trap,
                                              'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True
                if a.main_group == 'By Function':
                    new_element = SubElement(by_function, 'host-group',
                                             {'id': str(random.randint(1, 60000)), 'name': a.parent_group_1,
                                              'host-baselines': a.host_baseline_enable,
                                              'suppress-excluded-services': a.supress_excluded_service,
                                              'inverse-suppression': a.inverse_suppression,
                                              'host-trap': a.host_trap,
                                              'send-to-cta': a.sendtocta})
                    a._hasbeenadded = True
                    if a.ip_address_range != '':
                        ip = SubElement(new_element, 'ip-address-ranges')
                        ip.text = a.ip_address_range
                        a._hasbeenadded = True


    # Pretty Print USE >> For OUTPUTTING THE XML
    sub_outside= Element.append(root,create_outside('stealthwatch_og.xml'))

    bxml = tostring(root, encoding='utf8', method='xml')
    sxml = str(bxml, 'utf-8')

    x = xml.dom.minidom.parseString(sxml).toprettyxml(indent="   ")

    print(x)




















