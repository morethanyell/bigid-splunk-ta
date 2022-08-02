import json
import os
import sys
import requests
import hashlib
import random
from splunklib.modularinput import *
import splunklib.client as client

class BigIdAuditLogs(Script):
    
    MASK = "***ENCRYPTED***"
    CREDENTIALS = None
    CHECKPOINT_HEADER = "---START OF CHECKPOINTING---"
    CHECKPOINT_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'tmp', 'CHECKPOINT'))
    
    def get_scheme(self):
        scheme = Scheme("BigID Audit Logs")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "BigID Token Credentials"

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
        
        try:
            if r.status_code != 200:
                ew.log("ERROR", f'Unsuccessful HTTP request for BigID Refresh Token endpoint. status_code={str(r.status_code)}')
                sys.exit(1)
            
            return r.json()["systemToken"]
        except Exception as e:
            ew.log("ERROR", "Error getting audit logs: %s" % str(e))
            sys.exit(1)
    
    def get_audit_logs(self, ew, _base_url, _auth_token):
        
        base_url = _base_url + '/api/v1'
        endpoint_auditlogs = '/audit-log'
        url = base_url + endpoint_auditlogs
        
        headers = {
            'Authorization': _auth_token,
            'Content-Type': 'application/json'
        }
        
        try:
            r = requests.get(url=url, headers=headers)
        
            if r.status_code != 200:
                ew.log("ERROR", f'Unsuccessful HTTP request for BigID Audit Log endpoint. status_code={str(r.status_code)}')
                sys.exit(1)
                
            return r
        
        except Exception as e:
            ew.log("ERROR", "Error getting audit logs: %s" % str(e))
            sys.exit(1)
            
    def append_checkpoint(self, ew, _chkpt, mode):
        
        ew.log("INFO", f'Appending checkpoint to: {self.CHECKPOINT_FILE_PATH}')
        
        with open(self.CHECKPOINT_FILE_PATH, mode) as f:
            f.write(f'{_chkpt}\n')
            f.close()
    
    def read_tail(self, ew):
        
        tail = self.CHECKPOINT_HEADER
        
        if not os.path.exists(self.CHECKPOINT_FILE_PATH):
            
            ew.log("INFO", f'Expected checkpoint file is not found. Creating new a one: {self.CHECKPOINT_FILE_PATH}')
            
            with open(self.CHECKPOINT_FILE_PATH, "a+") as f:
                f.write(f'{tail}\n')
                f.close()
            
            ew.log("INFO", f'New checkpoint file has been successfully created.')
            
        with open(self.CHECKPOINT_FILE_PATH, "r+") as f:
            all_lines = f.readlines()
            if len(all_lines) > 0:
                tail = all_lines[-1]
            f.close()
            
        return self.CHECKPOINT_HEADER if (tail == self.CHECKPOINT_HEADER) else tail.strip()
        
    def trim_checkpoint(self, ew, _size_to_truncate):
        
        with open(self.CHECKPOINT_FILE_PATH, 'r+') as f:
            file_contents = f.readlines()
            f.close()
        
        if len(file_contents) > _size_to_truncate:
            
            ew.log("INFO", f'Removing first {str(_size_to_truncate)} lines of checkpoints.')
            
            new_contents = file_contents[_size_to_truncate:]
            new_contents = [self.CHECKPOINT_HEADER + '\n', *new_contents]
            
            with open(self.CHECKPOINT_FILE_PATH, 'w') as f:
                for l in new_contents:
                    l = l.strip()
                    f.write(f'{l}\n')
                f.close()
        
    
    def stream_events(self, inputs, ew):
        
        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        base_url = self.input_items["base_url"]
        token_name = self.input_items["token_name"]
        auth_token = self.input_items["auth_token"]

        ew.log("INFO", f'Collecting BigID Audit Logs from: {str(base_url)}')
        
        try:
            if auth_token != self.MASK:
                self.encrypt_keys(token_name, auth_token, session_key)
                self.mask_credentials(base_url, token_name, self.input_name, session_key)
            
            decrypted = self.decrypt_keys(token_name, session_key)
            self.CREDENTIALS = json.loads(decrypted)
            auth_token = self.CREDENTIALS["authToken"]
            
            # Retrieve checkpoint 
            checkpoint_hash = self.read_tail(ew)
            ew.log("INFO", f'Checkpoint retrieved: {checkpoint_hash}.')
            
            ew.log("INFO", f'Refreshing token on {base_url} with token (secret) length: {str(len(auth_token))}')
            r_rt = self.refresh_token(ew, base_url, auth_token)
            
            ew.log("INFO", 'Token refreshed. Now retrieving audit logs...')
            r_al = self.get_audit_logs(ew, base_url, r_rt)
            audit_dumps = r_al.text.splitlines()
            total_audit_dumps = len(audit_dumps)
            
            ew.log("INFO", f'Audit logs retrieved. A total of {str(total_audit_dumps)} lines. Now working on checkpoint matching...')
            index_to_start = -1
            
            if checkpoint_hash != self.CHECKPOINT_HEADER:
                ew.log("INFO", f'Checkpoint is not empty. Starting with new events only. Searching audit dumps for a checkpoint match...')
                for ad in audit_dumps:
                    index_to_start = index_to_start + 1
                    ad_line_hash = hashlib.sha256(ad.strip().encode())
                    ad_line_hash = ad_line_hash.hexdigest()
                    if checkpoint_hash == ad_line_hash: 
                        ew.log("INFO", f'Checkpoint found. Starting at line: {str(index_to_start)}.')
                        break
                if index_to_start > total_audit_dumps:
                    ew.log("INFO", f'No checkpoint found: {str(index_to_start)}/{len(total_audit_dumps)}. All audit logs will be indexed.')

            else:
                ew.log("INFO", f'Checkpoint is empty. All audit logs will be indexed.')
            
            new_audit_logs = audit_dumps[index_to_start + 1:]
            
            ew.log("INFO", f'Done writing/appending new checkpoint. Now indexing events...')
            
            for line in new_audit_logs:
                auditLine = Event()
                auditLine.stanza = self.input_name
                auditLine.sourceType  = "bigid:audit"
                auditLine.data = line
                ew.write_event(auditLine)
            
            ew.log("INFO", f'Successfully indexed {str(len(new_audit_logs))} BigID audit logs.')
            
            # Create checkpoint 
            new_checkpoint = new_audit_logs[len(new_audit_logs) - 1]
            new_checkpoint_hash = hashlib.sha256(new_checkpoint.strip().encode())
            new_checkpoint_hash = new_checkpoint_hash.hexdigest()
            self.append_checkpoint(ew, new_checkpoint_hash, 'a+')
            
            # Trim checkpoint file only half of the time
            if random.random() < .5:
                self.trim_checkpoint(ew, 3000)
            
            
        except Exception as e:
            ew.log("ERROR", "Error streaming events: %s" % str(e))
            

if __name__ == "__main__":
    sys.exit(BigIdAuditLogs().run(sys.argv))
    