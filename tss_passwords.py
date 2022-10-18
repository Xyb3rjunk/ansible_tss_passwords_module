#/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: tss_passwords

short_description: Create and Update Thycotic Secret Server Passwords

# Written when 2.9 was out
version_added=2.9

description: An Ansible module which uses Thycotic's Secret Server API to generate and update stored passwords. The name and description of options has been designed to replicate the community tss_lookup module where possible and practical. 

options:
    action:
        default: search
        description:
            - search: Search the Secret Server for a password
            - update: Update a stored password in Secret Server. If secret_password is not provided, a random password will be generated.
            - generate_password: Generate a password as the return value when set to `true`. Cannot be used to set the password for a specified secret - instead the return value must be used in another stanza [future state]. 
            - generate_token: Generate an API token using the `username` and `password` options when set to `true`. This can then be registered as a variable and sent to subsequent requests.
            - test_api: Test connectivity and API token. To be used as validation prior to changes.
         required: true
        type: str
        choices: ['search', 'update', 'generate_password', 'generate_token', 'test_api']
    api_path_uri:
        default: /SecretServer/api/v1
        description: 
            - The path to append to the base URL to form a valid REST API Request.
        required: false
        type: str
    base_url:
        description: 
            - The URL for the Secret Server. Excludes the API endpoint. 
            - Example: https://secretserver.example.com
        required: false
    token:
        description: The token used for Secret Server API authentication. If a token isn't already granted, use `generate_token: true` to toggle into token generation, retrieve a token and pass the stdout to this option in the proceeding stanzas.
        required: false
        type: str
    secret_folder:
        alias: key_name
        description:
            - The Folder containing the entry to be updated in Secret Server 
            - This module will attempt to find the secret based off the secret_name if this value is not provided, however, it is best to include it if possible.
        required: false
        type: str
    secret_name:
        alias: value_name
        description: 
            - The name of the entry to be updated in Secret Server
            - Mandatory if `generate_token or generate_password` are not in use
        required: false
        type: str
    secret_password:
        description: The password of the entry to be updated in Secret Server
        required: false
        type: str
    secret_notes:
         description: Notes which should accompany the secret. Will append to existing notes.
         required: false
         type: str
    site_id:
        default: 1
        description: The site ID in Secret Server in which the secret is located - used primarily for multi-tenancies instances.
        required: false
        type: int
    token_path_uri:
        default: /SecretServer/oauth2/token 
        description: The path to append to the base URL to form a valid OAuth2 Access Grant request.
        required: false
        type: str
    username:
        description:
            - Username used when requesting a token - only use if a token needs to be generated each time.
            - Required when I(generate_token) is set to `true` (defaults to false).
        required: false
        type: str
    password:
        description:
            - Password used when requesting a token - only use if a token needs to be generated each time.
            - Required when I(generate_token) is set to `true` (defaults to false).
        required: false
        type: str
    permit_empty_secrets:
        default: false
        description:
            - Used to override the default behaviour of generating a random secret when the secret_password value is empty.
        required: false
        type: bool
    verify_https:
        default: true
        description: If set to false, attempt to ignore certificate errors. NOT RECOMMENDED.
        required: false
        type: bool
# FINDME Needs to be configured - not yet ready for Galaxy. Name used is a placeholder - global replace on file when ready
extends_documentation_fragment:
    - xyb3rjunk.cred_management.tss_passwords 
author:
    - Xyb3r (@Xyb3rjunk)
'''
#FINDME Examples needs updating after refactor / amalgamation into action option and other design changes
EXAMPLES = r'''
# Generate an API token
- name: Generate an API token
  xyb3rjunk.cred_management.tss_passwords:
    base_url: "https://secretserver.example.com"
    username: "{{ ss_username }}"
    password: "{{ ss_password }}"
    generate_token: true
  register: generated_ss_token
  when: not ss_token

# Test connectivity and API authentication to the Secret Server
- name: Validate Connectivity and token
  xyb3rjunk.cred_management.tss_passwords:
    base_url: "{{ ss_base_url }}"
    token: "{{ generated_ss_token.stdout | default(ss_token) }}"
    test_api: true
  register: validate_ss_token
    
# Generate a password for the provided secret
- name: Generate a password for the secret
  xyb3rjunk.cred_management.tss_passwords:
    base_url: "{{ ss_base_url }}"
    token: "{{ generated_ss_token.stdout | default(ss_token) }}"
    generate_password: true
  register: generated_ss_password
  when: not target_password

# Use Generated token to change a password
- name: Change the target secret and notify password update handler on success
  xyb3rjunk.cred_management.tss_passwords:
    secret_folder: "Production Servers\databases\{{ target_server }}" 
    secret_name:  root
    secret_password: "{{ generated_ss_password.stdout | default(target_password)}}"
    base_url: "{{ ss_base_url }}"
    token: "{{ generated_ss_token.stdout | default(ss_token) }}"
  when: validate_ss_token is success
  notify: password_updater
'''

RETURN = r'''
# FINDME add return values
secret_id: 
    description: The ID of the secret in Secret Server
    type: str
    returned: When a password search is performed and a match is found
#FINDME - find documentation of what should be with `returned:` - free text or should it be specific values? and also a sample ID for `sample`

secret_name:
    description: The secret name in secret server
    type: str
    returned: When a password search is performed and a match is found
    sample: "Prod Server root"

secret_value:
    description: The secret password. The sample password in this example should NEVER be used.
    type: str
    returned: When a password search is performed and a match is found
    sample: batteryhorsestaple
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.utils.display import Display
import os
import requests
import sys

# Try blocks from tss_lookup and may be abandoned if not used https://github.com/ansible-collections/community.general/blob/main/plugins/lookup/tss.py
try:
    from thycotic.secrets.server import SecretServer, SecretServerError
    HAS_TSS_SDK = True
except ImportError:
    SecretServer = None
    SecretServerError = None
    HAS_TSS_SDK = False

try:
    from thycotic.secrets.server import PasswordGrantAuthorizer, DomainPasswordGrantAuthorizer, AccessTokenAuthorizer
    HAS_TSS_AUTHORIZER = True
except ImportError:
    PasswordGrantAuthorizer = None
    DomainPasswordGrantAuthorizer = None
    AccessTokenAuthorizer = None
    HAS_TSS_AUTHORIZER = False

def validate_module_args(module):
    # Python/Ansible should handle action not matching one of the choices so not validated

    # Initialise arrays for error handling
    warning = []
    fatal_errors = []
    # There should never be a case where Python gets to this point without base_url being defined but included in case
    if not module.param['base_url']:
        fatal_errors.append("base_url was not provided and is a mandatory parameter")
    
    # Validate necessary parameters present for token generation
    if module.param['action'] == "generate_token":
        # Note that this runs before generate_token and tests on a different variable to the token generated
        if module.param['token']:
            warning.append("generate_token: Should not specify token when requesting a token! Ignoring provided token.")
        if not module.param['username']:
            fatal_errors.append("Cannot generate token without including username in the request!!!")
        if not module.param['password']:
            fatal_errors.append("Cannot generate token without including username in the request!!!")

    # Validate necessary parameters for everything else
    if not module.param['action'] == "generate_token":
        if not module.param['token']:
            fatal_errors.append("Token is a required option when not requesting a token!!!")
        if not (module.param['action'] == "generate_password" or module.param['action'] == "test_api"):
            if not module.param['secret_name']:
                fatal_error.append("The secret_name parameter is mandatory when not generating a token or password!!!")
            if not module.param['action'] == "search":
                if not module.param['secret_password'] and not module.params['permit_empty_secrets']:
                    warning.append("No value was set in secret_password. A password will be generated for this secret.")
                elif not module.param['secret_password']:
                    results['msg'] = "No value was set in secret_password, continuing as permit_empty_secrets was enabled."
    return warning 
    return fatal_errors

def api_request(api_params):
    try:
        if api_params['api_method'] == "get":
            requests.get(api_params['api_path'], api_params['api_request_args'])
        elif api_params['api_method'] == "post":
            requests.post(api_params['api_path'], api_params['api_request_args'])
        else:
            method_exception_raised = True
        # This is very blanket and doesn't actually validate output. Mainly used for the test_api action 
        if method_exception_raised:
            response = "The API method failed to be sent to the api_request function or was an invalid value (must be post or get, received \"" + api_method + " \" instead)."
        else:
            response = "success"
    except requests.ConnectionError:
        response = "Connection Error encountered when attempting to connect to Secret Server."
    except requests.Timeout:
        response = "Timeout occurred when attempting to connect to Secret Server."
    except KeyboardInterrupt:
        response = "Exited due Keyboard interrupt"
    return response

def validate_api(api_params):
    # Use the healthcheck to validate the token
    api_params['api_path'] = api_params['api_path'] + "/healthcheck"
    response = api_request(api_params) 
    if response == "success":
        result = {'changed': False, 'failed': False, 'msg': 'API test successful'}
    else: 
        result = {'changed': False, 'failed': True, 'msg': response}
    return result

def search_password(api_params, secret_params):
    api_params['api_path'] = api_params['api_path'] + "secrets/lookup?filter.includeRestricted=true&filter.searchText=" + secret_params['secret_name'] + ""
    search_results = api_request(api_params)
    #FINDME need to verify name is returned from the secrets/lookup api endpoint in addition to the secrets endpoint
    # Return the secret value as stdout - this should be the expected return value
    if search_results['name'].lower() == secret_params['secret_name'].lower(): 
        stdout = search_results['value'] 
        result = {'changed': False, 'failed': False, 'stdout': stdout, 'secret_id': search_results['id'], 'secret_name': search_results['name'], 'secret_value': search_results['value']} 
    else:
        Display().warning('Secret not found with name ' + secret_params['secret_name'] + '!')
        result =  {'changed': False, 'failed': False, 'secret_id': "", 'secret_name': "", 'secret_value': "", 'msg': "Secret not found with provided criteria"} 
        raise SecretNotFound


def generate_password(api_params):
    api_params['api_path'] = api_params['api_path'] + "secret-templates/generate-password/7"
    generated_password = api_request(api_params)
    #FINDME - is a specific field in the JSON which should be extracted?
    result = {'changed': True, 'failed': False, 'stdout': generated_password.json()}

#FINDME - add ability to append notes to entries inside this function?
def update_password(api_params, secret_params):
#FINDME
    if not secret_params['secret_password'] and not secret_params['permit_empty_secret']:
       secret_params['secret_password'] = generate_password(api_params) 
      
    # Search for password and update it. If not found, create a new one under the provided path - if path/folder not provided exit.
    try:
        secret_details = search_password(secret_params)
        # Wrap arguments in a dict for the JSON request

        #FINDME. Work in progress here - the search function will need updating to support these variables. Should the json and request
        # be outside of the try function
        json_body = {
            'name': secret_params['secret_name'], 
            'site_id': secret_params['site_id'],
            'update_notes': secret_details['notes'] + "\n" + secret_params['secret_notes'],
            'secret_id': secret_details['secret_id']
            'folder_id': secret_details['folder_id']
        }
        api_params['json'] = "json=" + json_body

    except SecretNotFound:
        # Attempt to create a new secret entry
        # If the folder is not provided, fail
        if not secret_params['secret_folder']:
            result = {'changed': False, 'failed': True, 'stderr': "Secret not found with provided criteria. Unable to generate a new entry as the folder was not provided."}
            raise FolderNotFound
        #
        

     
    
def generate_api_token(api_params):
    # API endpoint for password generation
    api_params['api_path'] = api_params['api_path'] + "/oauth2/token"
    generated_token = api_request(api_params)

    # Update authentication method
    api_auth_header = {'Authorization': "Bearer {}".format(generated_token)}
    auth_method = "headers=" + api_auth_header
    api_params['api_request_args'] = auth_method + "verify=" + module.params['verify_https'] 

    # Test token
    result = validate_api(api_params)
    # If the test was successful, return the generated token inside stdout
    if not result['failed']:
        result['stdout'] = generated_token
    if result['failed']:
        result['msg'] = "Could not successfully generate a valid token. Message/token is " + generated_token
    # Return the results
    return result


def run_module():
    # Define available arguments that can be passed to this module
    module_args = {
        'action': {'type': 'str', 'required': False, 'default': 'search', 'choices': ['search','update','generate_password','generate_token', 'test_api'] },
        'api_path_uri': {'type': 'str', 'required': False, 'default': '/SecretServer/v1/api'},
        'base_url': {'type': 'str', 'required': True},
        'token': {'type': 'str', 'required': False},
        'secret_folder': {'type': 'str', 'required': False},
        'secret_name': {'type': 'str', 'required': False},
        'secret_password': {'type': 'str', 'required': False},
        'secret_notes': {'type': 'str', 'required': False},
        'site_id': {'type': 'int', 'required': False, 'default': 1},
        'token_path_uri': {'type': 'str', 'required': False, 'default': '/SecretServer/oauth2/token'},
        'username': {'type': 'str', 'required': False},
        'password': {'type': 'str', 'required': False},
        'permit_empty_secrets': {'type': 'bool', 'default': False, 'required': False},
        'verify_https': {'type': 'bool', 'required': False, 'default': True}
    }

    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = False
    )
    
    ### Declare params groups to make passing variables easier
    ## Auth params - for requesting tokens
    auth_params = {
         'username': module.params['username'],
         'password': module.params['password']
    }
    ## Secret properties
    secret_params = {
        'secret_name': module.params['secret_name'],
        'secret_password': module.params['secret_password'],
        'secret_folder': module.params['secret_folder'],
        'secret_notes': module.params['secret_notes'],
        'site_id': module.params['site_id'],
        'permit_empty_secrets': module.params['permit_empty_secrets']
    }

    ## Connection properties
    # Declare header as it must be a dict. Added support for API Token generation into the main API request
    if action == "generate_token":
        auth_params['grant_type'] = "password"
        auth_method = "body=" + auth_params
    else:
        api_auth_header = {'Authorization': "Bearer {}".format(module.params['token'])}
        auth_method = "headers=" + api_auth_header

    # Determine if API uses get or post off of type of action
    if action in ("search", "test_api"):
        api_method = "get"
    elif action in ("update", "generate_password", "generate_token"):
        api_method = "post"
    
    # Create a dict of all API parameters. Added seperate api_verify for generate_token to be able to validate the token
    api_params = {
        'api_path': module.params['base_url'] + module.params['api_path_uri'],
        'api_method': api_method,
        'api_request_args': auth_method + "verify=" + module.params['verify_https']
        'api_verify': "verify=" + module.params['verify_https']
    }

    ## Pre-flight checks
    # Validate the correct parameters have been used
    # FINDME : will this return the values
    validate_module_args(module)
    if warnings:
        Display().warning(warnings)
    if fatal_errors:
        # All fatal_errors are options errors as opposed to generic "AnsibleError"s
        #FINDME does this exit?
        AnsibleOptionsError(fatal_errors)

    ## Perform API actions
    #FINDME: populate values once functions set up
    if action == "search":
        result = search_password(api_params, secret_params)
    elif action == "update":
        result = update_password(api_params, secret_params)
    elif action == "generate_password":
        # secret_params sent for future work
        result = generate_password(api_params, secret_params)
    elif action == "generate_token":
        result = generate_api_token(api_params)
    elif action == "test_api":
        result = validate_api(api_params)

    #FINDME update return codes, add logic for state in Ansible - possibly resolved


def main():
    run_module()

if __name__ == '__main__':
   main()
