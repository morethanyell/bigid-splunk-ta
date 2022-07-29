import json
import os
import sys
import requests
import hashlib
import datetime, time
from splunklib.modularinput import *
import splunklib.client as client

class BigIdAuditLogs(Script):
    
    MASK = "***ENCRYPTED***"
    CREDENTIALS = None
    EMPTY_LOG = "<<EMPTY>>"
    
    def get_scheme(self):
        scheme = Scheme("BigId Audit Logs")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "BigId Token Credentials"

        base_url = Argument("base_url")
        base_url.title = "URL"
        base_url.data_type = Argument.data_type_string
        base_url.description = "E.g. https://sandbox.bigid.tools"
        base_url.required_on_create = True
        base_url.required_on_edit = True
        scheme.add_argument(base_url)
        
        token_name = Argument("token_name")
        token_name.title = "Token Name"
        token_name.data_type = Argument.data_type_string
        token_name.description = "Token Name"
        token_name.required_on_create = True
        token_name.required_on_edit = True
        scheme.add_argument(token_name) 

        auth_token = Argument("auth_token")
        auth_token.title = "Authorization Token"
        auth_token.data_type = Argument.data_type_string
        auth_token.description = "Authorization Token"
        auth_token.required_on_create = True
        auth_token.required_on_edit = True
        scheme.add_argument(auth_token)
        
        return scheme
    
    def validate_input(self, definition):
        pass
    
    def encrypt_keys(self, _token_name, _auth_token, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"tokenName": _token_name, "authToken": _auth_token}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _token_name:
                    service.storage_passwords.delete(username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _token_name)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))
    
    def decrypt_keys(self, _token_name, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _token_name:
                return storage_password.content.clear_password
    
    def mask_credentials(self, _base_url, _token_name, _input_name, _session_key):

        try:
            args = {'token': _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "base_url": _base_url,
                "token_name": _token_name,
                "auth_token": self.MASK
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))
    
    def refresh_token(self, ew, _base_url, _auth_token):
        
        base_url = _base_url + '/api/v1'
        endpoint_refresh = '/refresh-access-token'
        url = base_url + endpoint_refresh
        
        headers = {
            'Authorization': _auth_token,
            'Content-Type': 'application/json'
        }
        
        r = requests.get(url=url, headers=headers)
        
        if r.status_code != 200:
            ew.log("ERROR", "Unsuccessful HTTP request for BigId Audit Log endpoint. status_code=: %s" % str(r.status_code))
            sys.exit(1)
            
        return r.json()["systemToken"]
    
    def get_audit_logs(self, ew, _base_url, _auth_token):
        
        base_url = _base_url + '/api/v1'
        endpoint_auditlogs = '/audit-log'
        url = base_url + endpoint_auditlogs
        
        headers = {
            'Authorization': _auth_token,
            'Content-Type': 'application/json'
        }
        
        return requests.get(url=url, headers=headers)
    
    def tmp_file():
        today = datetime.date.today()
        tmp_path = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'tmp'))
        return os.path.join(tmp_path, f'{today}.log')
            
    def write_to_tail(self, _new_lines, mode):
        
        expected_file_path = self.tmp_file()
        
        with open(expected_file_path, mode) as f:
            for line in _new_lines:
                f.write(f'{line}\n')
            
    def read_tail(self, ew):
        
        tail = ""
        file_path_to_read = ""
        today = datetime.date.today()
        tmp_path = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'tmp'))
        expected_file_path = self.tmp_file()
        
        if not os.path.exists(expected_file_path):
            file_path_to_read = os.path.join(tmp_path, f'{today - datetime.timedelta(days = 1)}.log')
            ew.log("INFO", f'Creating new tmp file: {expected_file_path}')
            with open(expected_file_path, "a+") as f:
                f.close()
        else:
            file_path_to_read = expected_file_path
        
        with open(file_path_to_read, "r+") as f:
            first_line = f.read(1)
            if not first_line:
                tail = self.EMPTY_LOG
            else:
                tail = f.readlines()[-1]
            
        return tail
    
    def delete_tmp_files(self):
        tmp_path = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'tmp'))
        now = time.time()
        for f in os.listdir(tmp_path):
            f = os.path.join(tmp_path, f)
            if os.stat(f).st_mtime < now - (7 * 86400):
                if os.path.isfile(f):
                    os.remove(os.path.join(tmp_path, f))
        
    def stream_events(self, inputs, ew):
        
        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        base_url = self.input_items["base_url"]
        token_name = self.input_items["token_name"]
        auth_token = self.input_items["auth_token"]

        ew.log("INFO", f'Collecting BigId Audit Logs from: {str(base_url)}')
        
        try:
            if auth_token != self.MASK:
                self.encrypt_keys(token_name, auth_token, session_key)
                self.mask_credentials(base_url, token_name, self.input_name, session_key)
            
            decrypted = self.decrypt_keys(token_name, session_key)
            self.CREDENTIALS = json.loads(decrypted)

            auth_token = self.CREDENTIALS["authToken"]
            
            ew.log("INFO", f'Refreshing token on {base_url} with token (secret) length: {str(len(auth_token))}')
            r_rt = self.refresh_token(ew, base_url, auth_token)
            
            ew.log("INFO", f'Token refreshed. Now retrieving audit logs...')
            r_al = self.get_audit_logs(ew, base_url, r_rt)
            audit_dumps = r_al.text.splitlines()
            
            ew.log("INFO", f'Audit logs retrieved. A total of {str(len(audit_dumps))} lines. Working on checkpoint...')
            
            index_to_start = -1
            checkpoint = self.read_tail(ew)
            
            checkpointHash = hashlib.sha256(checkpoint.encode())
            
            ew.log("INFO", f'Checkpoint hash is: {checkpointHash}.')
            
            if checkpoint == self.EMPTY_LOG:
                self.write_to_tail(audit_dumps, 'w+')
            else:
                for ad in audit_dumps:
                    index_to_start = index_to_start + 1
                    if str(checkpoint).strip() == str(ad).strip(): break
            
            new_audit_logs = audit_dumps[index_to_start + 1:]
            
            self.write_to_tail(new_audit_logs, 'a+')
            
            for event in new_audit_logs:
                e = Event()
                e.stanza = self.input_name
                e.sourcetype = "bigid:audit"
                e.data = event
                ew.write_event(event)
            
            ew.log("INFO", f'Successfully indexed {str(len(new_audit_logs))} BigID audit logs.')
            
        except Exception as e:
            ew.log("ERROR", "Error: %s" % str(e))
            
        self.delete_tmp_files()

if __name__ == "__main__":
    sys.exit(BigIdAuditLogs().run(sys.argv))
    