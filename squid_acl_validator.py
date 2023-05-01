# https://www.visolve.com/squid/squid24s1/access_controls.html
# Case sensitive ???

# squid -k parse
# squid -k debug

## No Duplicates - Expandable till unique in all acl files ??
# No IP or domain duplicates
# No subdomains duplicates
# No host or Network IP inside a higher existing Network

## Valid IP
# Valid IPv4 or v6 Host, Network or range - ip-address/netmask

## Valid Domain
# valid url (start by .)

## Valid Regex
# regex

import enum, re, os, logging
import argparse, pdb
from typing import List, Optional, Sequence, TextIO

import ipaddress

from terminalwriter import TerminalWriter

# ipv4_range = r"^(25[0–5]|2[0–4][0–9]|[01]?[0–9][0–9]?).(25[0–5]|2[0–4][0–9]|[01]?[0–9][0–9]?).(25[0–5]|2[0–4][0–9]|[01]?[0–9][0–9]?).(25[0–5]|2[0–4][0–9]|[01]?[0–9][0–9]?)$"
REG_IP_RANGE = r"^((\d{1,3}\.){3}\d{1,3})-((\d{1,3}\.){3}\d{1,3}).*$"
# REG_IP_RANGE = r"^([0–9]{1,3}.){3}.([0–9]{1,3})-([0–9]{1,3}.){3}.([0–9]{1,3})$"
# REG_IPV4_HOST = r"^([0–9]{1,3}.){3}.([0–9]{1,3}))$"
# REG_IPV4_NET = r"^([0–9]{1,3}.){3}.([0–9]{1,3}))/([0–9]{1,2})$"
# REG_IP_HOST = r"^(([0–9]{1,3}.){3}.([0–9]{1,3}))|([a-fA-F0-9:])$"
# REG_IP_NET = r"^(([0–9]{1,3}.){3}.([0–9]{1,3}))|([a-fA-F0-9:])\/([0–9]{1,2})$"
# REG_IP_HOST_2 = r"^(([0–9]{1,3}.){3}.([0–9]{1,3})))|((([0–9A-Fa-f]{1,4}:){7}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){6}:[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){5}:([0–9A-Fa-f]{1,4}:)?[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){4}:([0–9A-Fa-f]{1,4}:){0,2}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){3}:([0–9A-Fa-f]{1,4}:){0,3}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){2}:([0–9A-Fa-f]{1,4}:){0,4}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){6}((b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b).){3}(b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b))|(([0–9A-Fa-f]{1,4}:){0,5}:((b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b).){3}(b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b))|(::([0–9A-Fa-f]{1,4}:){0,5}((b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b).){3}(b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b))|([0–9A-Fa-f]{1,4}::([0–9A-Fa-f]{1,4}:){0,5}[0–9A-Fa-f]{1,4})|(::([0–9A-Fa-f]{1,4}:){0,6}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){1,7}:))$"
# REG_IP_NET_2 = r"^(([0–9]{1,3}.){3}.([0–9]{1,3})))|((([0–9A-Fa-f]{1,4}:){7}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){6}:[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){5}:([0–9A-Fa-f]{1,4}:)?[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){4}:([0–9A-Fa-f]{1,4}:){0,2}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){3}:([0–9A-Fa-f]{1,4}:){0,3}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){2}:([0–9A-Fa-f]{1,4}:){0,4}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){6}((b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b).){3}(b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b))|(([0–9A-Fa-f]{1,4}:){0,5}:((b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b).){3}(b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b))|(::([0–9A-Fa-f]{1,4}:){0,5}((b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b).){3}(b((25[0–5])|(1d{2})|(2[0–4]d)|(d{1,2}))b))|([0–9A-Fa-f]{1,4}::([0–9A-Fa-f]{1,4}:){0,5}[0–9A-Fa-f]{1,4})|(::([0–9A-Fa-f]{1,4}:){0,6}[0–9A-Fa-f]{1,4})|(([0–9A-Fa-f]{1,4}:){1,7}:))/([0–9]{1,2})$"
REG_URL = r"^\.(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$"
REG_REG = r"^\^.*\$$" # To Defined
REG_IP_HOST = r"^((\d{1,3}\.){3}\d{1,3})$|^(.*:.*:.*(?!\/))$"
REG_IP_NET = r"^(((\d{1,3}\.){3}\d{1,3})|(.*:.*:.*))/.*$"
# REG_IP_NET = r"^(((\d{1,3}\.){3}\d{1,3})|(.*:.*:.*))/\d{1,2}$"

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class ValidationCode(enum.IntEnum):
  """Encodes the valid exit codes"""
  #: Tests passed.
  SUCCESS = 0
  #: Tests failed.
  FAILURE = 1
  #: Tests passed with Warnings.
  WARNING = 2

def flatten(list_of_lists):
    if len(list_of_lists) == 0:
        return list_of_lists
    if isinstance(list_of_lists[0], list):
        return flatten(list_of_lists[0]) + flatten(list_of_lists[1:])
    return list_of_lists[:1] + flatten(list_of_lists[1:])

class SquidACLItemReport:
  """Squid ACL Report item"""
  def __init__(self, 
               acl_validation_type:str, 
               code:ValidationCode, 
               acl_item:str, 
               message:str, 
               acl_line:str,
               acl_line_number:int,
               acl_filename:str):
    """
    Squid ACL report item

    :param acl_validation_type: Validation type ex. `Unknown`,`IP Host`,`IP Network`,...
    :type acl_validation_type: str
    :param code: Encodes a valid exit code
    :type code: ValidationCode
    :param acl_item: Expected ACL Item
    :type acl_item: str
    :param message: Exit detailed message
    :type message: str
    :param acl_line: Entire line of the ACL Item
    :type acl_line: str
    :param acl_line_number: ACL file line number
    :type acl_line_number: int
    :param acl_filename: ACL filename
    :type acl_filename: str
    """
    self.code = code
    self.acl_validation_type = acl_validation_type
    self.message = message
    self.acl_item = acl_item
    self.acl_line = acl_line
    self.acl_line_number = acl_line_number
    self.acl_filename = acl_filename
  
  def __repr__(self):
    return f"<SquidACLItemReport [{self.acl_item} <code: {self.code}>]>"
  
  def display(self)->List[str]:
    """
    Display the Squid ACL Validation in details

    :return: Strings with color mark
    :rtype: List[str]
    """
    text = []
    if self.code == ValidationCode.FAILURE:
      text = [
      "{bold}{red}_*_ "+self.acl_validation_type+" _*_{reset}",
      "",
      "  {bold}{red}"+self.acl_item+"{reset}",
      "> "+self.acl_line,
      "",
      "{bold}{red}"+self.acl_filename+"{reset}:"+str(self.acl_line_number)+": "+self.message,
      ]
    elif self.code == ValidationCode.WARNING:
      text = [
      "{bold}{yellow}_*_ "+self.acl_validation_type+" _*_{reset}",
      "",
      "  {bold}{yellow}"+self.acl_item+"{reset}",
      "> "+self.acl_line,
      "",
      "{bold}{yellow}"+self.acl_filename+"{reset}:"+str(self.acl_line_number)+": "+self.message,
      ]
    return text

  def display_inline(self)->str:
    """
    Short ACL Item display, `FAILED <filename>:<line number>::<acl_item> - <report message>`

    :return: Inline display
    :rtype: str
    """
    text = ""
    if self.code == ValidationCode.FAILURE: text += "FAILED "
    if self.code == ValidationCode.WARNING: text += "WARNING "
    if self.code == ValidationCode.SUCCESS: text += "SUCCESS "
    
    text += self.acl_filename+":"+str(self.acl_line_number)+"::"+self.acl_item+" - "+self.message

    return text


class SquidACLItem:
  """Squid ACL single Item"""
  def __init__(self, line:str, index:int, filename:str):
    """
    Squid ACL single Item 

    :param line: Entire Squid ACL file line
    :type line: str
    :param index: File line number
    :type index: int
    :param filename: ACL Filename
    :type filename: str
    """
    self.line = line.strip().replace('\n', '') # Beautify line
    self.filename = filename
    self.index = index
    self.acl_item = self.line.split(' #')[0] # Item without comment
    self.report = None

  def validate(self, other_acl_items:list = []) -> SquidACLItemReport:
    """
    Validate Squid ACL Item intrisic and contextual through given ACL Item list.
    
    ACL intrisic validation types:
      * `IP Network`, IPv4 or IPv6 Network
      * `IP Host`, IPv4 or IPv6 Host
      * `IP Range`, IPv4 range
      * `URL Domain`, Domainname dot starts
      * `Regex`, **TODO**
    ACL contextual validation types:
      * `Exact Duplicate`, ACL Item exact duplicate
      * `Domain Overlap`, Domain wider or thinner than another
      * `Network Overlap`, IPv4 or IPv6 overlaps
      * `IP Host Duplicate`, IPv6 equivalence duplicates
      * `IP Host Overlap`,  **TODO** IP Host overlap with an existing network

    :param other_acl_items: List of ACL Items for contextual validation, defaults to []
    :type other_acl_items: list, optional
    :return: ACL Item report for statistic and beautify display
    :rtype: SquidACLItemReport
    """
    acl_validation_type = "Unknown"
    message = ""
    code = ValidationCode.FAILURE

    ## Intrisic Validation
    # Valid IPv4 or v6 Network
    if re.match(REG_IP_NET, self.acl_item, re.IGNORECASE):
      acl_validation_type = "IP Network"
      try:
        ip_network = ipaddress.ip_network(self.acl_item) # raise ValueFAILURE(f'{address!r} does not appear to be an IPv4 or IPv6 network')
        message, code = ip_network.__class__, ValidationCode.SUCCESS
      except ValueError as e: 
        message = f"<IPNetworkAddress> {e}"
        code = ValidationCode.FAILURE
      # TODO Warning, prefered CIDR notation instead of 10.0.0.0/255.0.0.0
    
    # Valid IPv4 or v6 Host
    elif re.match(REG_IP_HOST, self.acl_item, re.IGNORECASE):
      acl_validation_type = "IP Host"
      try:
        ip_address = ipaddress.ip_address(self.acl_item) # raise ValueFAILURE("{address!r} does not appear to be an IPv4 or IPv6 address")
        message, code = ip_address.__class__, ValidationCode.SUCCESS
      except ValueError as e:
        message = f"<IPHostAddress> {e}"
        code = ValidationCode.FAILURE
    
    # Valid range - ipv4-ipv4
    elif re.match(REG_IP_RANGE, self.acl_item):
      acl_validation_type = "IP Range"
      # If match with minimal IPRange Regex
      start_ip, end_ip = self.acl_item.split('-')
      message = "<IPv4AddressRange> "
      code = ValidationCode.SUCCESS
      
      try:
        start_ip = ipaddress.IPv4Address(start_ip)
      except ValueError as e:
        message += f"[1] {e} "
        code = ValidationCode.FAILURE
      try:
        end_ip = ipaddress.IPv4Address(end_ip)
      except ValueError as e:
        message += f"[2] {e}"
        code = ValidationCode.FAILURE
      
      if code != ValidationCode.FAILURE and start_ip >= end_ip: # type: ignore
        message, code = f"{message} {start_ip} isn't less than {end_ip}", ValidationCode.FAILURE
        
    # Valid url (start by .)
    elif re.match(REG_URL, self.acl_item):
      acl_validation_type = "URL Domain (dot starts)"
      message, code = "", ValidationCode.SUCCESS
      # TODO Warning message if TLD

    # Valid Regex
    # TODO regex

    else:
      message, code = f"Doesn't seems to be IP address (host, net or range), nor URL (start by dots), nor a Regex", ValidationCode.FAILURE

    ## Contextual tests
    for other_acl_item in other_acl_items:
      # Exact duplicate exists
      if self.acl_item == other_acl_item.acl_item:
        message = f"Duplicate has been found in {other_acl_item.acl_filename}:L{other_acl_item.acl_line_number}"
        acl_validation_type, code = "Exact Duplicate", ValidationCode.FAILURE
        break
      
      # Domains overlapping
      elif re.match(REG_URL, self.acl_item) and re.match(REG_URL, other_acl_item.acl_item):
        subdomain_exists = other_acl_item.acl_item.split(self.acl_item)[-1] == ''
        # ".mail.google.com".split(".google.com") = [".mail",'']
        wide_domain_exists = self.acl_item.split(other_acl_item.acl_item) == ''
        if wide_domain_exists:
          message = f"A larger domain \"{other_acl_item.acl_item}\" has been found in {other_acl_item.acl_filename}:L{other_acl_item.acl_line_number}"
          acl_validation_type, code = "Domain Overlap", ValidationCode.FAILURE
          break
        if subdomain_exists:
          message = f"A thinner domain \"{other_acl_item.acl_item}\" has been found in {other_acl_item.acl_filename}:L{other_acl_item.acl_line_number}"
          acl_validation_type, code = "Domain Overlap", ValidationCode.FAILURE
          break
      
      # Network overlapping
      elif re.match(REG_IP_NET, self.acl_item, re.IGNORECASE) and re.match(REG_IP_NET, other_acl_item.acl_item, re.IGNORECASE):
        try:
          self_net = ipaddress.ip_network(self.acl_item)
          other_net = ipaddress.ip_network(other_acl_item.acl_item)
          if isinstance(self_net, type(other_net)):
          # TypeError: fc00::/7 and 172.16.1.0/24 are not of the same version
            if self_net.subnet_of(other_net): # type: ignore
              # 172.16.1.0/24.subnet_of(172.16.0.0/16) => True
              message = f"A larger network \"{other_acl_item.acl_item}\" has been found in {other_acl_item.acl_filename}:L{other_acl_item.acl_line_number}"
              acl_validation_type, code = "IP Network Overlap", ValidationCode.FAILURE
              break
            if other_net.subnet_of(self_net): # type: ignore
              message = f"A thinner network \"{other_acl_item.acl_item}\" has been found in {other_acl_item.acl_filename}:L{other_acl_item.acl_line_number}"
              acl_validation_type, code = "IP Network Overlap", ValidationCode.FAILURE
              break
        except ValueError as e: 
          break
      
      # IP Host duplicates (in case of IPv6 equivalence)
      elif re.match(REG_IP_HOST, self.acl_item, re.IGNORECASE) and re.match(REG_IP_HOST, other_acl_item.acl_item, re.IGNORECASE):
        try:
          self_ip = ipaddress.ip_address(self.acl_item)
          other_ip = ipaddress.ip_address(other_acl_item.acl_item)
          if self_ip == other_ip:
            message = f"An equivalent IP \"{other_acl_item.acl_item}\" has been found in {other_acl_item.acl_filename}:L{other_acl_item.acl_line_number}"
            acl_validation_type, code = "IP Host Duplicate", ValidationCode.FAILURE
        except ValueError as e: 
          break
        except TypeError as e:  # TypeError: fc00::/7 and 172.16.1.0/24 are not of the same version
          break
      
      # Host in an existing network overlapping
      # TODO
      # acl_validation_type, code = "IP Host Overlap", ValidationCode.FAILURE
      
    self.report = SquidACLItemReport(code=code, 
                                acl_validation_type=acl_validation_type, 
                                acl_item=self.acl_item, 
                                message=str(message), 
                                acl_line=self.line, 
                                acl_line_number=self.index, 
                                acl_filename=self.filename)
    return self.report

class SquidACLFileReport:
  """Squid ACL File Report object"""
  def __init__(self, file_path:str):
    """
    Squid ACL File Report contains Squid ACL items report

    :param file_path: Squid ACL File Path
    :type file_path: str
    """
    self.file_path = file_path
    self.report_items = []
    self.failures = 0
    self.warnings = 0
    self.success = 0

  def __repr__(self):
    return f"<SquidACLFileReport [{len(self.report_items)} items <{self.failures} fail, {self.warnings} warn, {self.success} succ>]>"

  def add(self, report_item:SquidACLItemReport):
    """
    Add a Squid ACL report item to ACL file report

    :param report_item: Squid ACL item report validation result
    :type report_item: SquidACLItemReport
    """
    self.report_items.append(report_item)
    match report_item.code:
      case ValidationCode.WARNING: self.warnings += 1
      case ValidationCode.FAILURE: self.failures += 1
      # case ValidationCode.SUCCESS: self.success += 1 # eq to default
      case _: self.success += 1

  def score(self)->int:
    """
    Percent score of the Squid ACL file based on ACL items validation code

    :return: Validation score
    :rtype: int
    """
    return int(100 - self.failures / len(self.report_items) * 100)

  def get_items(self)->List[SquidACLItemReport]:
    """
    :return: List of Squid ACL items report in the file
    :rtype: List[SquidACLItemReport]
    """
    return self.report_items
  
  def display_inline(self)->str:
    """
    Beautified display in one line the Squid ACL file report

    :return: Short display with color markups
    :rtype: str
    """
    text = f"{self.file_path} "
    if self.failures:
      text += "{red}" + "F"*self.failures + "{reset} * {bold}{red}["+ str(self.score()) +"%]{reset}"
    else:
      text += "* {bold}{green}[100%]{reset}"
    return text
  
  # def display(self):
  #   self.stdout = [report.display() for report in self.report_items]

class SquidACLFile:
  """ Squid ACL file """
  def __init__(self, file_path:str, verbosity:int = 0):
    """
    Squid ACL file

    :param file_path: File path
    :type file_path: str
    """
    self.file_path = file_path
    self.verbosity = verbosity
    self.acl_items = []
    self.acl_file_report = SquidACLFileReport(file_path)

    with open(file_path, 'r') as f:
      if self.verbosity: logging.debug(f"Reading file {file_path}")
      lines = f.readlines()
      for idx, line in enumerate(lines): 
        self.acl_items.append(SquidACLItem(line, idx+1,self.file_path.split("/")[-1]))

  def validate(self, other_acl_items:list = [])->SquidACLFileReport:
    """
    Squid ACL file intrisic and contextual validation

    :param other_acl_items: ACL items of other files for contextual validation, defaults to []
    :type other_acl_items: list, optional
    :return: Squid ACL file report
    :rtype: SquidACLFileReport
    """
    for acl in self.acl_items:
      acl_item_report = acl.validate(other_acl_items) # Validate ACL item inside context
      other_acl_items.append(acl_item_report) # Add current ACL item report to contextual list
      self.acl_file_report.add(acl_item_report) # Add the current ACL report item to the file report
    return self.acl_file_report

class SquidACLReport:
  """ Squid ACL rule report contains files """
  def __init__(self, verbosity:int = 0):
    """ Squid ACL rule report with files """
    self.report_files = []
    self.report_items = []
    self.verbosity = verbosity
    self.failures = 0
    self.warnings = 0
    self.success = 0

  def __repr__(self)->str:
    return f"<SquidACLReport [{len(self.report_files)} files, {len(self.report_items)} items <{self.failures} err, {self.warnings} warn, {self.success} succ>]>"

  def add(self, report_file:SquidACLFileReport):
    """
    Add a Squid ACL file report to the global rule report

    :param report_file: Squid ACL file report
    :type report_file: SquidACLFileReport
    """
    self.report_files.append(report_file)
    for i in report_file.get_items():
      self.report_items.append(i)
    self.failures += report_file.failures
    self.warnings += report_file.warnings
    self.success += report_file.success

  def __iter__(self)->List[SquidACLFileReport]: return self.report_files

  def score(self):
    """
    :return: Global score based on Squid ACL items validation
    :rtype: int
    """
    return self.failures / len(self.report_items) * 100
  
  def display(self)->List[str]:
    """
    Display the entire Squid ACL report in stdout
    
    Skeleton:
    1. Introdution (collected items)
    2. Inline ACL file report display
    3. Failed validation items
    4. Warnings validation items
    5. Validations summary
    6. Result

    :return: Text with color marks
    :rtype: List[str]
    """
    tw = TerminalWriter()
    
    # Introduction
    text = [
      "{bold}=*= ACL Validation =*={reset}",
      "collected "+f"{len(self.report_items)}"+" ACL item in "+f"{len(self.report_files)}"+" files",
      ""]
    
    # Inline file report
    for report_file in self.report_files:
      text.append(report_file.display_inline())
    
    # Failed items
    if self.failures:
      text.append("=*= FAILURES =*=")
      for report_item in self.report_items:
        if report_item.code == ValidationCode.FAILURE:
          text.append(report_item.display())
    
    # ACL items with warnings
    if self.warnings:
      text.append("=*= WARNINGS =*=")
      for report_item in self.report_items:
        if report_item.code == ValidationCode.WARNING:
          text.append(report_item.display())
    
    # Summary of validations
    text.append("=*= Short validation summary info =*=")
    for report_item in self.report_items:
      if self.verbosity:
        text.append(report_item.display_inline())
      elif report_item.code == ValidationCode.FAILURE or report_item.code == ValidationCode.WARNING:
        text.append(report_item.display_inline())
      
    # Display result
    results = []
    if self.failures: results.append("{bold}{red}"+str(self.failures)+" failed{reset}")
    if self.success: results.append("{green}"+str(self.success)+" success{reset}")
    if self.warnings: results.append("{yellow}"+str(self.warnings)+" warnings{reset}")
    
    if self.failures:
      text.append("{red}=*={reset} "+", ".join(results)+"{red} in "+f"{len(self.report_files)}"+" files =*={reset}")
    else:
      text.append("=*= "+",".join(results)+" in "+f"{len(self.report_files)}"+" files =*=")
    
    tw.write_lines(flatten(text))
    
    return text


class SquidACL(object):
  """Squid ACL validator"""
  def __init__(self,
               files: list = [],
               file: str = "",
               verbosity: int = 0,
               *args, **kwargs):
    """
    Squid ACL validator

    :param files: List of files path, defaults to []
    :type files: list, optional
    :param file: Single file path, defaults to ""
    :type file: str, optional
    :param verbosity: _description_, defaults to 0
    :type verbosity: int, optional
    """
    
    self.verbosity = verbosity
    self.acl_files_report = SquidACLReport(self.verbosity)
    self.acl_files = []
    
    if files: self.add_files(files)
    if file: self.add_file(file)
  
  def add_files(self, file_paths:List[str]):
    """
    Add files to Squid ACL validator

    :param file_paths: Files to add
    :type file_paths: List[str]
    :raises FileNotFoundError: When file or directory not found
    """
    for p in file_paths:
      if not os.path.exists(p): raise FileNotFoundError(f"{p} was not found")
      if os.path.isdir(p):
        if self.verbosity > 1: logging.debug(f"{p} is a directory")
        files_list = os.listdir(p)
        if self.verbosity: logging.info(f"{p} found {len(files_list)} files")
        if self.verbosity > 1: logging.debug(f"add_files({files_list})")
        self.add_files([p+filename for filename in files_list])
      else:
        self.add_file(p)
  
  def add_file(self, file_path:str):
    """
    Add a single file to Squid ACL validator

    :param file_path: Filepath
    :type file_path: str
    :raises FileNotFoundError: When file not found
    """
    if not os.path.exists(file_path): raise FileNotFoundError(f"{file_path} was not found")
    self.acl_files.append(SquidACLFile(file_path, self.verbosity))
  
  def validate(self) -> SquidACLReport:
    """
    Squid ACL validation which contains ACL files

    :return: Squid ACL Report 
    :rtype: SquidACLReport
    """
    validated_report_items = []
    
    for acl_file in self.acl_files:
      acl_file_report = acl_file.validate(validated_report_items)
      validated_report_items += acl_file_report.get_items()
      self.acl_files_report.add(acl_file_report)
      
    return self.acl_files_report
  
  # TODO format (to reformat if no errors)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Squid ACL file validator")
  parser.add_argument(
    "-f", 
    "--files", 
    help="Files to test, no directories, you can use * (all files in folder level) or ** (all files in all sublfolders)", 
    required=True,
    nargs='+')
  parser.add_argument(
    "-v",
    "--verbosity",
    action="count",
    default=0,
    help="Increase stdout verbosity")
  args = parser.parse_args()
  
  args = vars(args)
  
  files_validator = SquidACL(**args)
  files_report = files_validator.validate()
  files_report.display()
