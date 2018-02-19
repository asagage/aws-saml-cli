#!/usr/local/bin/python

from __future__ import print_function
import sys
import boto3
import requests
import getpass
import ConfigParser
import base64
import xml.etree.ElementTree as ET
import re
import os
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse
import argparse
# import logging  # used when debug is enabled

##########################################################################
# Variables

USERNAME = os.environ.get('AWS_SAML_USERNAME', '')

# region: The default AWS region that this script will connect
# to for all API calls
REGION = 'us-east-1'

# output_format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
OUTPUT_FORMAT = 'json'

# aws_config_file: The file where this script will store the temp
# credentials under the saml profile
AWS_CONFIG_FILE = '/.aws/credentials'

# aws_token_file: The file where this script will store the temp
# credentials for shell env
AWS_TOKEN_FILE = '/.aws/.token_file'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
SSL_VERIFICATION = True

# idpentryurl: The initial url that starts the authentication process.
IDP_ENTRY_URL = 'https://<YOUR ADFS SERVER>/adfs/ls/IdpInitiatedSignOn.aspx' \
                '?loginToRp=urn:amazon:webservices'

# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)

# MFA Verification Option choice
# verificationOption0 = mobile app
# verificationOption1 = phone call
# verificationOption2 = sms
VERIFICATION_OPTION = 'verificationOption0'

##########################################################################


def decode_soup(response):
    to_parse = response.text.encode('utf8')
    return BeautifulSoup(to_parse, 'lxml')


def main(user_name, role_index):

    username = user_name or USERNAME
    # Get the federated credentials from the user
    if not username:
        print("Username not found. You may pass a username with option -u",
              "or set the AWS_SAML_USERNAME env variable.")
        print("Username (ex: username@company.com): ", end='')
        username = raw_input()

    password = getpass.getpass()
    print('')
    print('Sending a request to your MFA Device... Please check your Authenticator.')

    # Initiate session handler
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    form_response = session.get(IDP_ENTRY_URL, verify=SSL_VERIFICATION)
    # Capture the idp_auth_form_submit_url, which is the final url after all
    # the 302s
    idp_auth_form_submit_url = form_response.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    form_soup = decode_soup(form_response)
    payload = {}

    for input_tag in form_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        if "user" in name.lower():
            # Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            # Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            # Make an educated guess that this is the right field for the password
            payload[name] = password
        else:
            # Simply populate the parameter with the existing value (picks up
            # hidden fields in the login form)
            payload[name] = value

    # Set our AuthMethod to Form-based auth because the code above sees two values
    # for authMethod and the last one is wrong
    payload['AuthMethod'] = 'FormsAuthentication'

    # Debug the parameter payload if needed
    # Use with caution since this will print sensitive output to the screen

    # print payload

    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idp_auth_form_submit_url by combining the scheme and hostname
    # from the entry url with the form action target
    # If the action tag doesn't exist, we just stick with the
    # idp_auth_form_submit_url above
    for input_tag in form_soup.find_all(re.compile('(FORM|form)')):
        action = input_tag.get('action')
        loginid = input_tag.get('id')
        if (action and loginid == "loginForm"):
            parsed_url = urlparse(IDP_ENTRY_URL)
            idp_auth_form_submit_url = parsed_url.scheme + "://" + \
                parsed_url.netloc + action

    # print idp_auth_form_submit_url
    # print('')

    # Performs the submission of the IdP login form with the above post data
    login_response = session.post(
        idp_auth_form_submit_url, data=payload, verify=SSL_VERIFICATION)

    # Debug the response if needed
    # print(login_response.text)

    # MFA Step 1 - If you have MFA Enabled, there are one to two additional steps
    # to authenticate... possibly choose a verification option
    # and if so resubmit the page

    # Capture the idp_auth_form_submit_url, which is the final url after all
    # the 302s
    mfa_url = login_response.url

    login_soup = decode_soup(login_response)
    mfa_payload = {}

    for input_tag in login_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        # Simply populate the parameter with the existing value (picks up hidden
        # fields in the login form)
        mfa_payload[name] = value

    # Set mfa auth type here...
    mfa_payload['AuthMethod'] = 'AzureMfaServerAuthentication'

    # check to see if we have multiple options for verification
    do_resubmit = False
    if login_soup.find(id="linksDiv"):
        mfa_payload['__EVENTTARGET'] = VERIFICATION_OPTION
        do_resubmit = True
    else:
        # if not, just submit the form
        mfa_payload['Continue'] = 'Continue'

    mfa_response = session.post(mfa_url, data=mfa_payload, verify=SSL_VERIFICATION)

    # print(mfa_payload)
    # Debug the response if needed
    # print(mfa_response.text)

    # MFA Step 2 - Fire the form and wait for verification
    mfa_soup = decode_soup(mfa_response)
    resubmit_payload = {}

    if do_resubmit:
        for input_tag in mfa_soup.find_all(re.compile('(INPUT|input)')):
            name = input_tag.get('name', '')
            value = input_tag.get('value', '')
            # Simply populate the parameter with the existing value
            # (picks up hidden fields in the login form)
            resubmit_payload[name] = value

        resubmit_payload['AuthMethod'] = 'AzureMfaServerAuthentication'

        resubmit_response = session.post(
            mfa_url, data=resubmit_payload, verify=SSL_VERIFICATION)
    else:
        resubmit_response = mfa_response

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    # Debug the response if needed
    # print(resubmit_response.text)

    # # Decode the response and extract the SAML assertion
    saml_soup = decode_soup(resubmit_response)
    assertion = None

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for input_tag in saml_soup.find_all('input'):
        if(input_tag.get('name') == 'SAMLResponse'):
            # (input_tag.get('value'))
            assertion = input_tag.get('value')

    # Better error handling is required for production use.
    if not assertion:
        # TODO: Insert valid error checking/handling
        print('Response did not contain a valid SAML assertion.  Check your '
              'username/password and or mfa device and try again.')
        sys.exit(1)

    # Debug only
    # print(base64.b64decode(assertion))

    # Parse the returned assertion and extract the authorized roles
    aws_roles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') ==
                'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                aws_roles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for aws_role in aws_roles:
        chunks = aws_role.split(',')
        if 'saml-provider' in chunks[0]:
            newaws_role = chunks[1] + ',' + chunks[0]
            index = aws_roles.index(aws_role)
            aws_roles.insert(index, newaws_role)
            aws_roles.remove(aws_role)

    if role_index is not None:
        pass
    elif role_index is None and len(aws_roles) > 1:
        print('')
        # If I have more than one role, ask the user which one they want,
        # otherwise just proceed
        i = 0
        print("Please choose the role you would like to assume:")
        for aws_role in aws_roles:
            friendly_name = aws_role.split(',')[0].split('ADFS/')[1]
            print('[%s]:\t%s' % (i, friendly_name))
            i += 1
        print("Selection: ", end='')
        role_index = raw_input()
    else:
        role_index = 0

    try:
        role = aws_roles[int(role_index)].split(',')
        role_arn = role[0]
        principal_arn = role[1]
    except IndexError:
        print('You selected an invalid role index (%s), please try again' %
              role_index)
        sys.exit(1)

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    boto_session = boto3.Session()
    sts = boto_session.client('sts')
    sts_response = sts.assume_role_with_saml(
        RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)

    credentials = sts_response['Credentials']
    access_key_id = credentials['AccessKeyId']
    secret_access_key = credentials['SecretAccessKey']
    session_token = credentials['SessionToken']
    expiration_dtm = credentials['Expiration']

    # from boto.sts import STSConnection
    # sts_connection = STSConnection(profile_name=aws_profile)
    # conn = boto.sts.connect_to_region(REGION, sts_connection)
    # token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

    # Write the AWS STS token into the AWS credential file
    home = expanduser("~")
    file_name = home + AWS_CONFIG_FILE

    # Read in the existing config file
    config = ConfigParser.RawConfigParser()
    config.read(file_name)

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section('saml'):
        config.add_section('saml')

    config.set('saml', 'output', OUTPUT_FORMAT)
    config.set('saml', 'region', REGION)
    config.set('saml', 'aws_access_key_id', access_key_id)
    config.set('saml', 'aws_secret_access_key', secret_access_key)
    config.set('saml', 'aws_session_token', session_token)

    # Write the updated config file
    with open(file_name, 'w+') as config_file:
        config.write(config_file)

    # Also write the credentials to a token_file for putting directly into our
    # shell env with a bash/zsh alias function
    target = open(home + AWS_TOKEN_FILE, 'w')
    target.truncate()
    target.write(
        "export AWS_ACCESS_KEY_ID=\"%s\"\n" % access_key_id)
    target.write(
        "export AWS_SECRET_ACCESS_KEY=\"%s\"\n" % secret_access_key)
    target.write(
        "export AWS_SESSION_TOKEN=\"%s\"\n" % session_token)
    target.write(
        "export AWS_SECURITY_TOKEN=\"%s\"\n" % session_token)
    target.close()

    # Give the user some basic info as to what has just happened
    print('\n----------------------------------------------------------------')
    print('Your new access key pair has been stored in the AWS configuration '
          'file {0} under the \'saml\' profile.'.format(file_name))
    print ('Note that it will expire at {0}.'.format(expiration_dtm))
    print ('After this time, you may safely rerun this script to refresh your '
           'access key pair.')
    print ('To use this credential, call the AWS CLI with the --profile option '
           '(e.g. aws --profile saml ec2 describe-instances).')
    print ('----------------------------------------------------------------\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Use SAML to authenticate into AWS')
    parser.add_argument('-u', '--user', dest='user', help='your username@company.com')
    parser.add_argument('-r', '--role', dest='role_index', type=int,
                        help='the ID of the role you want to assume as it would be printed by '
                             'this CLI')
    args = parser.parse_args()

    user = args.user
    role_idx = args.role_index

    main(user, role_idx)
