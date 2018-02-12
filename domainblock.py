#!/usr/bin/env python
#Block malicious domains with IPAM WAPI
import sys, os, ConfigParser, requests, time
import logging
import httplib as http_client
import re

def block_domain(domain, comment):
    url = 'https://%(server)s/wapi/v2.2.2/record:cname' % conf
    headers = {'Content-Type': 'application/json'}
    json = """{ "name": "%s.%s", "comment": "%s", "canonical": "%s" }""" % (domain, zone, comment, zone)
    auth = (conf['username'], conf['password'])
    response = requests.post(url, data=json, headers=headers, allow_redirects=False, auth=auth)
    response.raise_for_status() 
    return response

def is_domain_already_blocked(domain):
    url = 'https://%(server)s/wapi/v2.2.2/record:cname?name={0}.{1}'.format(domain, zone) % conf
    auth = (conf['username'], conf['password'])
    response = requests.get(url, allow_redirects=False, auth=auth)
    response.raise_for_status() 
    return "_ref" in response.content

def debug_api():
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def read_config(filename="/services/service-user/conf/settings.ini", section="ipam"):
    ini_file = ConfigParser.ConfigParser()
    ini_file.read(filename)
    conf = dict(ini_file.items(section))
    return conf

def input_matches_regex(msg, regex=".", error_msg="invalid input"):
    while True:
        resp = raw_input(msg).rstrip()
        if resp == "":
            print "[!] You must enter a value"
            continue
        if not re.match(regex, resp):
            print "[!]", error_msg
            continue
        
        # Success!
        print "[*] You entered", resp
        return resp

def input_domain_to_block():
    while True:
        domain = input_matches_regex("Enter a domain to block (e.g., badguy.xyz): ", r'^(\*\.)?[^*\s]+$', "This domain you entered appears to be invalid")
        if is_domain_already_blocked(domain):
            print "[!] This domain appears to have already been blocked."
            continue
        return domain

def confirm(msg):
    a = raw_input(msg + "? [y/n] ")
    return a.lower() in ('y','yes','ok')

def main():
    logf = open("/services/service-user/var/log/rpz.log", "a")
    requester = os.environ['TTY_OWNER']
    conf = read_config()

    #Get domain from Analyst
    domain = input_domain_to_block()
    subdomain = "*."+domain
    blocksubdomain = False
    if not domain.startswith("*"):
        if is_domain_already_blocked(subdomain):
            print "[*] Note: "+subdomain+" is already blocked."
        elif confirm("[?] Do you also want to block "+subdomain):
            blocksubdomain = True

    #Get Jira ticket number and comment from Analyst
    jira = input_matches_regex("Enter Jira ticket # (e.g., IR-123456): ", '^[a-zA-Z]{3}\-\d{6}$', 'Please enter a valid Jira ticket #')
    extra_comment = input_matches_regex("Enter a comment:")
    comment = "Blocked by %s for %s: %s" % (requester, jira, extra_comment)
    print "[*] The following comment will be recorded in IPAM: '%s'" % comment

    if not confirm("Does everything look correct?"):
        print "[*] Ok, exiting"
        sys.exit(0)

    #Make the call to IPAM
    try:
        debug_api()
        response = block_domain(domain, comment)
        timestr = time.strftime("%Y-%m-%dT%H:%M:%S")
        print "\n{noformat}"
        print "[*] The domain "+domain+" was sinkholed at "+timestr+" in response to this incident.\n"
        logf.write("[succeeded] {0} {1} {2} {3} {4} \n".format(timestr, domain, response.status_code, response.reason, comment))

        if blocksubdomain:
            debug_api()
            response = block_domain(subdomain, comment)
            timestr = time.strftime("%Y-%m-%dT%H:%M:%S")
            print "[*] The domain "+subdomain+" was sinkholed at "+timestr+" in response to this incident."
            print "{noformat}\n"
            logf.write("[succeeded] {0} {1} {2} {3} {4} \n".format(timestr, subdomain, response.status_code, response.reason, comment))

    #Catch HTTP error codes and log them 
    except requests.exceptions.HTTPError as err:
        status_code = err.response.status_code
        status_reason = err.response.reason
        print "[!!] The server responded with code and reason", status_code, status_reason
        logf.write("{0} [{1}] {2} {3} {4} {5} [failed]\n".format(timestr, jira, domain, requester, status_code, status_reason))
        sys.exit(-1)
        
if __name__ == '__main__':
    zone = str("rpz-security.local")
    main()
