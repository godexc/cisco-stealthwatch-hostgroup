# Cisco Stealthwatch Host Group CSV to XML

During any Cisco Stealthwatch POC or deployment one thing takes time which is creating host groups. This code allows SEs or Customers to import a CSV file/convert it to an XML which can be parsed by Stealthwatch.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Just activate the virtualenv (https://virtualenv.pypa.io/en/stable/userguide/) but in any case, you should be able to run it on Python 3.6 and over.


### How it Works

Stealthwatch Enterprise expects a certain XML to import Host Groups. This code uses the template named as **"Stealthwatch_HG_Template.csv"** and you need to add your IP Subnets and Logical Groups to that piece. Use it as your guide.

CSV File has Multiple Columns that are very much self-explanatory.

Columns "Enable_Baselining","Send_to_CTA" and "Disable_Security_Events_for_Excluded_Services" are for the attributes of the logical host groups.

Column named "Main_Group" can be either "By Function" or "By Location" to keep the consistency on Stealthwatch Enterprise.

Columns named "Parent_Group 1", "Parent_Group 2", "Parent_Group 3" and "Parent_Group 4" where you create the nested groups. Currently, script supports up to 5 Nested Groups (including Main Group)

First 23 rows are there to keep the Host Group configuration schema of Stealthwatch Enterprise.

"stealthwatch_og.xml" has been taken out from a fresh Stealthwatch Enterprise install, it appends the necessary **Outside Hosts** to the custom XML file.

**Note:** This script only allows customer to modify their **Inside Hosts** and any modification for **Outside Hosts** needs to be done manually.


Script takes the "Stealthwatch_HG_Template.csv" sorts it out and creates "sorted.csv" then uses it to parse & pass the to XML Elements that we create on the run.

```
python csv_inventory.py >> output.xml
```

## Authors

* **Huseyin Efe Evyapan** - *hevyapan@cisco.com* 



