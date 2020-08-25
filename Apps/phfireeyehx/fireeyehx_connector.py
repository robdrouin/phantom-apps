# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

import json
import requests
import os
import uuid
import hashlib
import pytz
from zipfile import ZipFile
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
# Usage of the consts file is recommended
from fireeyehx_consts import *
# import pudb


class RetVal(tuple):

    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class FireeyeHxConnector(BaseConnector):

    def __init__(self):
        super(FireeyeHxConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._host = None
        self._port = None
        self._header = None

        return

    def _flatten_response_data(self, response):
        try:
            response_data = response.get('data', {})
            response.update(response_data)
            del response['data']
        except:
            pass

        return response

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Empty response and no information in the header'), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_octet_response(self, r, action_result):
        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            local_dir = ('{}/{}').format(Vault.get_vault_tmp_dir(), guid)
        else:
            local_dir = ('/opt/phantom/vault/tmp/{}').format(guid)

        self.save_progress(('Using temp directory: {0}').format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Unable to create temporary vault folder.', e)

        action_params = self.get_current_param()

        acq_id = action_params.get('acquisition_id', 'no_id')

        zip_file_path = ('{0}/{1}.zip').format(local_dir, acq_id)

        if r.status_code == 200:

            try:
                with open(zip_file_path, 'wb') as (f):
                    f.write(r.content)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to write zip file to disk. Error: {0}').format(str(e))), None)
            else:
                try:
                    zip_object = ZipFile(zip_file_path)
                    zip_object.extractall(pwd=self._zip_password, path=local_dir)
                except Exception as e:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to extract items from zip file. Error: {0}').format(str(e))), None)
                else:
                    try:
                        with open(local_dir + '/metadata.json') as (f):
                            metadata = json.load(f)
                        target_filename = metadata['req_filename']
                        full_target_path = local_dir + '/' + target_filename + '_'
                    except Exception as e:
                        return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to find target filename. Error: {0}').format(str(e))), None)

                try:
                    vault_results = Vault.add_attachment(full_target_path, self.get_container_id(), file_name=target_filename)
                    return RetVal(phantom.APP_SUCCESS, vault_results)
                except Exception as e:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to store file in Phantom Vault. Error: {0}').format(str(e))), None)

        message = ('Error from server. Status Code: {0} Data from server: {1}').format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process an octet response.
        # This is mainly for processing data downloaded during acquistions.
        if 'octet' in r.headers.get('Content-Type', ''):
            return self._process_octet_response(r, action_result)

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method='get', get_file=False, **kwargs):

        config = self.get_config()

        username = config.get('hx_username')
        password = config.get('hx_password')

        resp_json = None

        # Need to auth with the API first.
        # Authorization comes back in the X-FeApi-Token, which we send in all requests.
        self.save_progress('Auth Token Starting')

        try:
            login_url = self._base_url + FIREEYE_API_PATH + FIREEYE_LOGIN_LOGOUT_ENDPOINT

            self.save_progress('HX Auth: Execute REST Call')

            req = requests.get(login_url, auth=(username, password), verify=False, headers=self._header)

            # Add the authorization value to the header
            if req.status_code >= 200 and req.status_code <= 204:
                self.save_progress('HX Auth: Process Response - Token Success')

                self._header['X-FeApi-Token'] = req.headers.get('X-FeApi-Token')
            else:
                self.save_progress('HX Auth: Process Response - Token Failed')

                message = 'HX Auth Failed, please confirm username and password'

                return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        except requests.exceptions.RequestException as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)
        else:
            # Check to make sure the method is a valid Python Requests method
            try:
                request_func = getattr(requests, method)
            except AttributeError:
                return RetVal(action_result.set_status(phantom.APP_ERROR, ('Invalid method: {0}').format(method)), resp_json)

            # Create the URL for the endpoint
            url = self._base_url + FIREEYE_API_PATH + endpoint

            # Query the endpoint
            try:

                # If we are downloading a file from HX, we need to update the header.
                if get_file:
                    self._header.update({'Accept': 'application/octet-stream'})

                r = request_func(url, verify=config.get('verify_server_cert', False), headers=self._header, **kwargs)

            except requests.exceptions.RequestException as e:

                return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)

            else:
                # Logout of the API.
                # The Endpoint Security API has a default limit of 100 concurrent open sessions.
                # FireEye highly recommends that you close any session you open after you have
                # finished.
                try:
                    self.save_progress('HX Logout: Execute REST Call')

                    req = requests.delete(login_url, verify=False, headers=self._header)
                except requests.exceptions.RequestException as e:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used test connectivity to Akamai
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        endpoint = FIREEYE_VERSION_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_version(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_VERSION_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        if param.get('search'):
            params.update({'search': param.get('search')})

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_HOSTS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_GET_HOSTS_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host_alerts(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_GET_HOSTS_ALERTS_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host_acquisitions(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        agent_id = param.get('agent_id')

        if param.get('acquisition_type') == "File":
            endpoint = FIREEYE_LIST_ACQUISITION_FILES_HOST_ENDPOINT.format(agentId=agent_id)
        elif param.get('acquisition_type') == "Quarantine":
            endpoint = FIREEYE_LIST_QUARANTINE_FILES_HOST_ENDPOINT.format(agentId=agent_id)
        elif param.get('acquisition_type') == "Triage":
            endpoint = FIREEYE_LIST_TRIAGE_HOST_ENDPOINT.format(agentId=agent_id)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_file_acquisition(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        agent_id = param.get('agent_id')
        req_path = param.get('req_path')
        req_filename = param.get('req_filename')
        comment = param.get('comment')
        external_id = param.get('external_id')
        req_use_api = param.get('req_use_api', False)

        file_acq_data = {'req_path': req_path, 'req_filename': req_filename, 'comment': comment, 'external_id': external_id, 'req_use_api': req_use_api}

        endpoint = FIREEYE_CREATE_ACQUISITION_ENDPOINT.format(agentId=agent_id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='post', data=file_acq_data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_quarantine_acquisition(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        quarantineId = param.get('quarantine_id')

        endpoint = FIREEYE_CREATE_QUARANTINE_ACQUISITION_ENDPOINT.format(quarantineId=quarantineId)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='post')

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_triage_acquisition(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        quarantineId = param.get('quarantine_id')

        endpoint = FIREEYE_CREATE_QUARANTINE_ACQUISITION_ENDPOINT.format(quarantineId=quarantineId)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='post')

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_file_acquisitions(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        agent_id = param.get('agent_id', None)

        search = param.get('search', None)

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        if agent_id is not None:
            params['host._id'] = agent_id
        if search is not None:
            params['search'] = search

        endpoint = FIREEYE_LIST_FILE_ACQUISITIONS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_quarantine_acquisitions(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        agent_id = param.get('agent_id', None)

        search = param.get('search', None)

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')
        params['sort'] = "_id:descending"

        if agent_id is not None:
            params['host._id'] = agent_id
        if search is not None:
            params['search'] = search

        endpoint = FIREEYE_LIST_QUARANTINE_FILES_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_data_acquisitions(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        agent_id = param.get('agent_id', None)

        search = param.get('search', None)

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        if agent_id is not None:
            params['host._id'] = agent_id
        if search is not None:
            params['search'] = search

        endpoint = FIREEYE_LIST_DATA_ACQUISITIONS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_triage_acquisitions(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        agent_id = param.get('agent_id', None)

        search = param.get('search', None)

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        if agent_id is not None:
            params['host._id'] = agent_id
        if search is not None:
            params['search'] = search

        endpoint = FIREEYE_LIST_TRIAGE_ACQUISITIONS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_acquisition_status(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if param.get('acquisition_type') == "File":
            endpoint = FIREEYE_GET_FILE_ACQUISITION_ENDPOINT.format(acqsId=param.get('acquisition_id'))
        elif param.get('acquisition_type') == "Quarantine":
            endpoint = FIREEYE_GET_QUARANTINE_ACQUISITION_ENDPOINT.format(quarantineId=param.get('acquisition_id'))
        elif param.get('acquisition_type') == "Triage":
            endpoint = FIREEYE_GET_TRIAGE_ACQUISITION_ENDPOINT.format(acqsId=param.get('acquisition_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if param.get('acquisition_type') == "File":
            endpoint = FIREEYE_GET_FILE_ACQUISITION_PACKAGE_ENDPOINT.format(acqsId=param.get('acquisition_id'))
        elif param.get('acquisition_type') == "Quarantine":
            endpoint = FIREEYE_GET_QUARANTINE_ACQUISITION_PACKAGE_ENDPOINT.format(quarantineId=param.get('acquisition_id'))
        elif param.get('acquisition_type') == "Triage":
            endpoint = FIREEYE_GET_TRIAGE_ACQUISITION_PACKAGE_ENDPOINT.format(acqsId=param.get('acquisition_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result, get_file=True)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_triages(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_LIST_TRIAGE_ACQUISITIONS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_system_info(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_GET_HOST_SYS_INFO_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_CONTAINMENT_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result, method='post')

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_quarantine_status(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_CONTAINMENT_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_CONTAINMENT_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete')

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_quarantine_approved(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        contain_data = {'state': 'contain'}

        endpoint = FIREEYE_CONTAINMENT_ENDPOINT.format(agentId=param.get('agent_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result, method='patch', data=contain_data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_host_sets(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        name = param.get('name', None)

        if name is not None:
            params['name'] = name

        endpoint = FIREEYE_LIST_HOST_SET_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        # for e in response.get('data', {}).get('entries', []):
        #    action_result.add_data(e)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host_set(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_HOST_SET_LIST_HOST_ENDPOINT.format(hostSetId=param.get('host_set_id'))

        search_data = {'offset': 0}
        HARD_LIMIT = 10000
        stop = False
        while not stop:
            ret_val, response = self._make_rest_call(endpoint, action_result, params=search_data)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            response = self._flatten_response_data(response)
            # for e in response.get('data', {}).get('entries', []):
            #    action_result.add_data(e)
            action_result.add_data(response)

            total = response.get('data', {}).get('total', 0)
            offset = response.get('data', {}).get('offset', 0)
            limit = response.get('data', {}).get('limit', 0)
            new_offset = offset + limit
            self.debug_print(('Total: {}; New Offset: {}').format(total, new_offset))
            stop = new_offset >= HARD_LIMIT or new_offset >= total
            search_data['offset'] = new_offset

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_GET_ALERT_ENDPOINT.format(alertId=param.get('alert_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_suppress_alert(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_SUPPRESS_ALERT_ENDPOINT.format(alertId=param.get('alert_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete')

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        if param.get('filter_query'):
            params['filterQuery'] = param.get('filter_query')

        endpoint = FIREEYE_LIST_ALERTS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alert_groups(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        if param.get('filter_query'):
            params['filterQuery'] = param.get('filter_query')

        endpoint = FIREEYE_LIST_ALERT_GROUPS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_group(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_ALERT_GROUP_ENDPOINT.format(alertGroupId=param.get('alert_group_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alert_group_alerts(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_LIST_ALERT_GROUP_ALERTS_ENDPOINT.format(alertGroupId=param.get('group_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alert_filters(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FRIEEYE_LIST_ALERT_FILTERS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert_filter(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_GET_ALERT_FILTER_ENDPOINT.format(alertFilterId=param.get('alert_filter_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alert_group_filters(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_FILTER_ALERT_ALERT_GROUP_ENDPOINT.format(filterId=param.get('filter_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_indicators(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_INDICATORS_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_indicators_category(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_INDICATORS_CATEGORY_ENDPOINT.format(category=param.get('category'))

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_indicators(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        endpoint = FIREEYE_GET_INDICATOR_ENDPOINT.format(category=param.get('category'), indicator=param.get('indicator'))

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_conditions_indicator(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_CONDITIONS_INDICATOR_ENDPOINT.format(category=param.get('category'), indicator=param.get('indicator'))

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_conditions_indicator_type(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_CONDITIONS_INDICATOR_TYPE_ENDPOINT.format(category=param.get('category'), indicator=param.get('indicator'), type=param.get('type'))

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_indicator_categories(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_LIST_INDICATOR_CATEGORIES_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_indicator_category(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        endpoint = FIREEYE_GET_INDICATOR_CATEGORY_ENDPOINT.format(category=param.get('category'))

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_policies(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        params['limit'] = param.get('limit')
        params['offset'] = param.get('offset')

        if param.get('combined'):
            params['combined'] = param.get('combined')

        endpoint = FIREEYE_LIST_POLICIES_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_policy(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_GET_POLICY_ENDPOINT.format(policyId=param.get('policy_id'))

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_policy(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        # Defaults for appending new data
        excluded_md5s = param.get("excluded_md5s", None)
        excluded_files = param.get("excluded_files", None)
        excluded_paths = param.get("excluded_paths", None)
        excluded_processes = param.get("excluded_processes_names", None)

        policyId = param.get('policy_id')

        # Hold which category we are going to add the exclusions too
        categories = []

        if param.get("malware_protection"):
            categories.append("malware_protection")
        if param.get("exploit_guard_protection"):
            categories.append("exploit_guard_protection")
        if param.get("real_time_indicator_detection"):
            categories.append("real_time_indicator_detection")

        md5s = []
        files = []
        paths = []
        processes = []

        # Need to get the policy details first
        endpoint = FIREEYE_GET_POLICY_ENDPOINT.format(policyId=policyId)

        ret_val, response = self._make_rest_call(endpoint, action_result)

        policy = self._flatten_response_data(response)

        for category in categories:

            if policy.get("data").get("data").get(category).get("excludedMD5s"):
                md5s = policy.get("data").get("data").get(category).get("excludedMD5s")

                policy["data"][category]["excludedMD5s"] = md5s + excluded_md5s.split(',')

            if policy.get("data").get("data").get(category).get("excludedFiles"):
                files = policy.get("data").get("data").get(category).get("excludedFiles")

                policy["data"][category]["excludedFiles"] = files + excluded_files.split(',')

            if policy.get("data").get("data").get(category).get("excludedPaths"):
                paths = policy.get("data").get("data").get(category).get("excludedPaths")

                policy["data"][category]["excludedPaths"] = paths + excluded_paths.split(',')

            if policy.get("data").get("data").get(category).get("excludedProcesses"):
                processes = policy.get("data").get("data").get(category).get("excludedProcesses")

                policy["data"][category]["excludedProcesses"] = processes + excluded_processes.split(',')

        data = json.dumps(policy)

        endpoint = FIREEYE_UPDATE_POLICY_ENDPOINT.format(policyId=policyId)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params, method="put", data=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_quarantine_files(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = FIREEYE_LIST_QUARANTINE_FILES_ENDPOINT

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(response)
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # pudb.set_trace()

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get the config to get timezone parameter
        config = self.get_config()

        interval_mins = int(config.get('ingest').get('interval_mins'))

        params = {}

        # Maximum limit of 32-bit signed binary integer. Limit imposed on FE Console.
        params['limit'] = int(2147483647)

        # If timezone is not set then cancel. We need the timezone to set the correct query times for ingestion.
        try:
            tz = config.get('timezone')
        except:
            return action_result.set_status(phantom.APP_ERROR, "Asset configuration timezone is not set.")

        # If it is a manual poll or first run
        if self.is_poll_now() or self._state.get('first_run', True):
            start_time = datetime.now(pytz.timezone(tz)) - timedelta(minutes=interval_mins)

        # If it is a scheduled poll, ingest from last_ingestion_time
        else:
            start_time = datetime.strptime(self._state.get('last_ingestion_time', datetime.now(pytz.timezone(tz)) - timedelta(minutes=interval_mins)), "%Y-%m-%dT%H:%M:%S.%fZ")

        # End time is current time stamp
        end_time = datetime.now(pytz.timezone(tz))

        # Print the times in an acceptable format for Fireeye
        start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        end_time = end_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Create the filter were will use to query Fireeye
        query = [{"operator": "between", "arg": [start_time, end_time], "field": "first_event_at"}]

        # Dump the query.
        filterQuery = json.dumps(query)

        # Note we need to replace all the spaces since python.requests adds + to spaces and screws up the query.
        params['filterQuery'] = "{}".format(filterQuery.replace(" ", ""))

        endpoint = FIREEYE_LIST_ALERT_GROUPS_ENDPOINT

        ret_val, alerts_list = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(alerts_list)
        action_result.add_data(response)

        if response:

            self.save_progress('Ingesting {} alerts'.format(len(response['entries'])))

            for alert in response['entries']:

                # Create a container for each alert
                container_creation_status, container_id = self._create_container(alert)

                if phantom.is_fail(container_creation_status) or not container_id:
                    self.debug_print('Error while creating container with ID {container_id}. {error_msg}'.
                                format(container_id=container_id, error_msg=container_creation_status))
                    continue
                else:
                    # Create artifacts for specific alert
                    artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(alert=alert,
                                                                                            container_id=container_id)

                    if phantom.is_fail(artifacts_creation_status):
                        self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.
                                        format(container_id=container_id, error_msg=artifacts_creation_msg))
        else:
            self.save_progress('No alerts found')

        # Store it into state_file, so that it can be used in next ingestion
        self._state['first_run'] = False
        self._state['last_ingestion_time'] = end_time

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _convert_timestamp_to_string(self, timestamp, tz):
        """ This function is used to handle of timestamp converstion for on_poll action.
        :param timestamp: Epoch time stamp
        :param tz: Timezone configued in the Asset
        :return: datetime string
        """

        date_time = datetime.fromtimestamp(timestamp, pytz.timezone(tz))

        return date_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def _create_container(self, alert):
        """ This function is used to create the container in Phantom using alert data.
        :param alert: Data of single alert
        :return: status(success/failure), container_id
        """
        container_dict = dict()

        container_dict['name'] = "{alert_name}".format(alert_name=alert['assessment'])
        container_dict['source_data_identifier'] = "{alert_group_id}".format(alert_group_id=alert['_id'])
        container_dict['description'] = "FireEye HX alert for {assessment} detected on host {host} for the file {file}".format(assessment=alert['assessment'],
                                                                                                        host=alert['grouped_by']['host']['hostname'],
                                                                                                        file=alert['file_full_path'])

        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress('Error while creating container for alert {alert_name}. '
                               '{error_message}'.format(alert_name=alert['assessment'], error_message=container_creation_msg))
            return self.set_status(phantom.APP_ERROR)

        return self.set_status(phantom.APP_SUCCESS), container_id

    def _create_artifacts(self, alert, container_id):
        """ This function is used to create artifacts in given container using alert data.
        :param alert: Data of single alert
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """
        artifacts_list = []

        detections_dict, alert = self._process_artifact_detections(alert, container_id)
        artifacts_list.append(detections_dict)

        alert_dict, alert = self._process_artifact_alert(alert, container_id)
        artifacts_list.append(alert_dict)

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifacts_list)

        if phantom.is_fail(create_artifact_status):
            return self.set_status(phantom.APP_ERROR), create_artifact_msg

        return self.set_status(phantom.APP_SUCCESS), 'Artifacts created successfully'

    def _process_artifact_detections(self, alert, container_id):
        """ This function is used to create the artifact detections using the data from the alert.
        :param alert: Data of single alert
        :return: dictionary of detections to be added as artifact(s)
        """
        cef = {}
        actor_process = {}
        cef_types = {}
        temp_dict = {}

        for last_alert in alert['last_alert']:
            # Process the event values
            if last_alert == "event_values":
                for event_values in alert['last_alert'][last_alert]:
                    # Grab the detection data.
                    if event_values == "detections":
                        # Process the detection's data.
                        i = 0
                        for detections in alert['last_alert'][last_alert][event_values]:
                            for detection in alert['last_alert'][last_alert][event_values][detections][i]:
                                if detection == "action":
                                    if alert['last_alert'][last_alert][event_values][detections][i][detection]['actioned-object']['object-type'] == "file":
                                        name = alert['last_alert'][last_alert][event_values][detections][i][detection]['actioned-object']['object-type']
                                        detection_file_name = "{}_{}".format(name, i)
                                        cef[detection_file_name] = alert['last_alert'][last_alert][event_values][detections][i][detection]['actioned-object']['file-object']
                                # Skip the infected object since it is repeated with the data from the actioned-object json
                                elif detection == "infected-object":
                                    continue
                                else:
                                    cef[detection] = detection
                            i += 1
                    # Process the scanned object data.
                    elif event_values == "scanned-object":
                        scanned_object_type = alert['last_alert'][last_alert][event_values]["scanned-object-type"]
                        for so in alert['last_alert'][last_alert][event_values][scanned_object_type]:
                            if so == "actor-process":
                                for actor in alert['last_alert'][last_alert][event_values][scanned_object_type][so]:
                                    if alert['last_alert'][last_alert][event_values][scanned_object_type][so][actor] == "user":
                                        for userdata in alert['last_alert'][last_alert][event_values][scanned_object_type][so][actor]:
                                            actor_process[userdata] = alert['last_alert'][last_alert][event_values][scanned_object_type][so][actor]
                                    else:
                                        actor_process[actor] = alert['last_alert'][last_alert][event_values][scanned_object_type][so][actor]
                            else:
                                actor_process[so] = alert['last_alert'][last_alert][event_values][scanned_object_type][so]
                        cef["actor-process"] = actor_process
                    else:
                        cef[last_alert] = alert['last_alert'][last_alert]
            else:
                cef[last_alert] = alert['last_alert'][last_alert]

        # Transform the Alert id into its own field name so we can add a type to it
        cef['alert_id'] = cef['_id']
        del cef['_id']

        # Transform the hosts id into its own field name so we can add a type to it
        cef['agent']['host_id'] = cef['agent']['_id']
        del cef['agent']['_id']

        # Sort keys to make it easier to read
        # cef = json.dumps(cef, sort_keys=True)

        # Remove the data we just parse. No need to be there anymore when processing the other artifacts.
        del alert['last_alert']

        cef_types["alert_id"] = ["fireeyehx alert id"]
        cef_types["md5sum"] = ["fileHash", "fileHashMd5"]
        cef_types["sha256sum"] = ["fileHashSha256"]
        cef_types["sha1sum"] = ["fileHashSha1"]
        cef_types["file-path"] = ["filePath"]
        cef_types["path"] = ["filePath"]
        cef_types["file_full_path"] = ["filePath"]
        cef_types["pid"] = ["pid"]
        cef_types["hostname"] = ["sourceHostName"]
        cef_types["host_id"] = ["fireeyehx agentid"]
        cef_types["fileWriteEvent/username"] = ["sourceUserId"]
        cef_types["fileWriteEvent/processPath"] = ["filePath"]
        cef_types["fileWriteEvent/process"] = ["deviceProcessName"]
        cef_types["fileWriteEvent/fullPath"] = ["filePath"]
        cef_types["fileWriteEvent/fileName"] = ["fileName"]
        cef_types["fileWriteEvent/filePath"] = ["filePath"]
        cef_types["fileWriteEvent/md5"] = ["fileHash", "fileHashMd5"]
        cef_types["fileWriteEvent/parentProcessPath"] = ["deviceProcessName"]

        # Add into artifacts dictionary if it is available
        if cef:
            temp_dict['cef'] = cef
            temp_dict['cef_types'] = cef_types
            temp_dict['name'] = "HX Detection"
            temp_dict['container_id'] = container_id
            temp_dict['type'] = "event"
            temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)

        return temp_dict, alert

    def _process_artifact_alert(self, alert, container_id):
        """ This function is used to create the artifact detections using the data from the alert.
        :param alert: Data of single alert
        :return: dictionary of detections to be added as artifact(s)
        """
        cef = {}
        cef_types = {}
        temp_dict = {}

        for data in alert:
            if data == "grouped_by":
                for grouped in alert[data]:
                    cef[grouped] = alert[data][grouped]
            else:
                cef[data] = alert[data]

        # Transform the hosts id into its own field name so we can add a type to it
        cef['host']['host_id'] = cef['host']['_id']
        del cef['host']['_id']

        # cef = json.dumps(cef, sort_keys=True)

        cef_types["_id"] = ["fireeyehx alertgroup id"]
        cef_types["md5sum"] = ["fileHash", "fileHashMd5"]
        cef_types["file-path"] = ["filePath"]
        cef_types["file_full_path"] = ["filePath"]
        cef_types["hostname"] = ["sourceHostName"]
        cef_types["primary_ip_address"] = ["ip"]
        cef_types["host_id"] = ["fireeyehx agentid"]

        # Add into artifacts dictionary if it is available
        if cef:
            temp_dict['cef'] = cef
            temp_dict['cef_types'] = cef_types
            temp_dict['name'] = "HX Alert Details"
            temp_dict['container_id'] = container_id
            temp_dict['type'] = "event"
            temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)

        return temp_dict, alert

    def _process_artifact_host(self, alert, container_id):
        """ This function is used to create the artifact host using the data from the alert.
            This will seperate the host and os details from the rest of the alert
        :param alert: Data of single alert
        :return: dictionary of detections to be added as artifact(s) and the updated alert data
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict({})))

        # Get all the information about the host
        endpoint = FIREEYE_GET_HOSTS_ENDPOINT.format(agentId=alert.get("last_alert").get("agent").get("_id"))

        host_data = self._make_rest_call(endpoint, action_result)

        temp_dict = {}
        cef = {}
        cef_types = {}
        cef_types["last_alert"] = {}

        cef_types["last_alert"]["_id"] = ["fireeyehx alert id"]
        cef_types["_id"] = ["fireeyehx agentid"]
        cef_types["hostname"] = ["sourceHostName"]
        cef_types["primary_ip_address"] = ["ip"]
        cef_types["last_poll_ip"] = ["ip"]

        cef = host_data['data']

        # Add into artifacts dictionary if it is available
        if cef:
            temp_dict['cef'] = cef
            temp_dict['cef_types'] = cef_types
            temp_dict['name'] = "HX Host Details"
            temp_dict['container_id'] = container_id
            temp_dict['type'] = "host"
            temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)

        return temp_dict

    def _create_dict_hash(self, input_dict):
        """ This function is used to generate the hash from dictionary.
        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """
        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.
        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """
        self.debug_print('action_id', self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'get_version': self._handle_get_version,
            'get_quarantine_status': self._handle_get_quarantine_status,
            'set_quarantine_approved': self._handle_set_quarantine_approved,
            'quarantine_device': self._handle_quarantine_device,
            'unquarantine_device': self._handle_unquarantine_device,
            'start_file_acquisition': self._handle_start_file_acquisition,
            'start_quarantine_acquisition': self._handle_start_quarantine_acquisition,
            'get_acquisition_status': self._handle_get_acquisition_status,
            'list_file_acquisitions': self._handle_list_file_acquisitions,
            'list_quarantine_acquisitions': self._handle_list_quarantine_acquisitions,
            'list_data_acquisitions': self._handle_list_data_acquisitions,
            'list_triage_acquisitions': self._handle_list_triage_acquisitions,
            'list_endpoints': self._handle_list_endpoints,
            'get_system_info': self._handle_get_system_info,
            'get_file': self._handle_get_file,
            'list_triages': self._handle_list_triages,
            'list_host_sets': self._handle_list_host_sets,
            'get_host_set': self._handle_get_host_set,
            'get_host': self._handle_get_host,
            'get_host_alerts': self._handle_get_host_alerts,
            'get_host_acquisitions': self._handle_get_host_acquisitions,
            'get_alert': self._handle_get_alert,
            'suppress_alert': self._handle_suppress_alert,
            'list_alerts': self._handle_list_alerts,
            'list_alert_groups': self._handle_list_alert_groups,
            'get_alert_group': self._handle_get_alert_group,
            'list_alert_group_alerts': self._handle_list_alert_group_alerts,
            'get_alert_filter': self._handle_get_alert_filter,
            'list_alert_filters': self._handle_list_alert_filters,
            'list_alert_group_filters': self._handle_list_alert_group_filters,
            'list_indicators': self._handle_list_indicators,
            'list_indicators_category': self._handle_list_indicators_category,
            'get_indicator': self._handle_get_indicators,
            'list_conditions_indicator': self._handle_list_conditions_indicator,
            'list_conditions_indicator_type': self._handle_list_conditions_indicator_type,
            'list_indicator_categories': self._handle_list_indicator_categories,
            'get_indicator_category': self._handle_get_indicator_category,
            'list_policies': self._handle_list_policies,
            'get_policy': self._handle_get_policy,
            'update_policy': self._handle_update_policy,
            'on_poll': self._handle_on_poll
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        return action_execution_status

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._host = config.get('hx_hostname')
        self._port = config.get('hx_port')
        self._base_url = "{}:{}".format(self._host, self._port)
        self._header = {
            'X-Requested-With': 'REST API',
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }
        self._zip_password = config.get('zip_password', 'unzip-me')
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    # import pudb
    import argparse

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = FireeyeHxConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FireeyeHxConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
