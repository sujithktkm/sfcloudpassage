import base64
import json
import time
import logging
import sys
from threading import Thread

import requests

__author__ = 't_sujithk'

access_token = ''


class Server:
    def __init__(self, url='', id='', hostname='', ip_address='', connecting_ip='', group_name='', fqdn='',
                 connecting_fqdn=''):
        # cmd.Cmd.__init__(self)
        logging.info("Init invoked")
        self.url = url
        self.id = id
        self.hostname = hostname
        self.ip_address = ip_address
        self.connecting_ip = connecting_ip
        self.group_name = group_name
        self.fqdn = fqdn
        self.connecting_fqdn = connecting_fqdn
        logging.info("Init function call finished")

    def write(self):
        logging.info("write method call invoked, returns Server object")
        return [self.id, self.url, self.hostname, self.fqdn, self.ip_address, self.connecting_ip, self.connecting_fqdn,
                self.group_name]


def do_get_uri(url, access_type='R'):
    """
    :param url: URL that should be hit to obtain necessary information from cloudpassge
    :return: Returns a JSON object
    """
    logging.info("In get_uri method call")
    if not url:
        logging.info("No url provided, exiting")
        sys.exit(2)
    logging.info("Arguments provided: %s", str(url))
    global access_token
    if not access_token:
        logging.info("Access token not found. Trying to get one using get_token method call")
        logging.info("Accessing get token method")
        do_get_token(access_type)

    logging.info("Access token: %s", str(access_token))
    headers = {"Content-Type": "application/json;charset=UTF=8", "Cache-Control": "no-store", "Pragma": "no-cache",
               "Authorization": "Bearer " + access_token}
    logging.info("Header information for making a get_uri request to cloudpassage: %s", str(headers))
    logging.info("URL being hit: %s", str(url))
    response_uri = requests.get(url, headers=headers)
    logging.info("Status code of response: %s", str(response_uri.status_code))
    if response_uri.status_code == 200:
        logging.info("Request went through correctly, success")
        jsonobj = json.loads(response_uri.text)
        logging.info("Finished get_uri method call")
        logging.info("JSON obj from get_uri request: %s", str(jsonobj))
        # return jsonobj
    else:
        logging.info("Request failed, %s", str(response_uri.status_code))
        logging.info("Finished get_uri method call")
        logging.info("Status code returned from get_uri method call: %s", str(response_uri.status_code))
        sys.exit(2)


def do_get_all_servers(groups='', access_type='R', filen=''):
    """
    :param groups: group name on which you want the inventory
    :return: a dictionary of servers indexed on the id
    """
    global access_token
    logging.info("In get_all_servers method call")
    logging.info("Argument passed: %s", str(groups))
    url_cp = "https://api.cloudpassage.com/v1/servers?group_name="
    logging.info("url being invoked, to retrieve all servers from input group value: %s", str(url_cp))
    servers = {}
    if not groups:
        logging.info("Making a call to get_token to get access token to retrieve all groups")
        do_get_token(access_type)
        logging.info("Access token: %s", str(access_token))
        headers = {"Content-Type": "application/json;charset=UTF=8", "Cache-Control": "no-store",
                   "Pragma": "no-cache", "Authorization": "Bearer " + access_token}
        logging.info("Header information for making a get_uri request to cloudpassage: %s", str(headers))
        url = "https://api.cloudpassage.com/v1/groups"
        logging.info("Getting all groups from: %s", str(url))
        response_uri = requests.get(url, headers=headers)
        logging.info("Status code of response: %s", str(response_uri.status_code))
        if response_uri.status_code == 200:
            logging.info("Request went through correctly, success")
            jsonobj = json.loads(response_uri.text)
            logging.info("JSON obj from get groups request: %s", str(jsonobj))
            for group in jsonobj['groups']:
                logging.info("Group name: %s", str(group['name']))
                url_group_member = url_cp + group['name']
                logging.info("Calling get_cp method using this url: %s", str(url_group_member))
                response = do_get_cp(url_group_member, access_type, filen)
                logging.info("Response obtained from get_cp method call: %s", str(response))
                for server in response['servers']:
                    logging.info("Adding info about this server to 'servers' list: %s", str(server['id']))
                    servers[server['id']] = Server(url=server['url'], id=server['id'], hostname=server['hostname'],
                                                   ip_address=server['interfaces'][0]['ip_address'],
                                                   connecting_ip=server['connecting_ip_address'],
                                                   group_name=server['group_name'], fqdn=server['reported_fqdn'],
                                                   connecting_fqdn=server['connecting_ip_fqdn'])
        else:
            logging.info("Request failed, %s", str(response_uri.status_code))
            logging.info("Finished no groups found, finished get_all_servers method call")
            logging.info("Status code returned from get_all_servers method call: %s", str(response_uri.status_code))
            sys.exit(2)
    else:
        # for group in groups:
        logging.info("Group name: %s", str(groups))
        if isinstance(groups, list):
            for group in groups:
                logging.info("Group name: %s", str(group))
                url_group_member = url_cp + group
                logging.info("Calling get_cp method using this url: %s", str(url_group_member))
                response = do_get_cp(url_group_member, access_type, filen)
                logging.info("Response obtained from get_cp method call: %s", str(response))
                for server in response['servers']:
                    logging.info("Adding info about this server to 'servers' list: %s", str(server['id']))
                    servers[server['id']] = Server(url=server['url'], id=server['id'], hostname=server['hostname'],
                                                   ip_address=server['interfaces'][0]['ip_address'],
                                                   connecting_ip=server['connecting_ip_address'],
                                                   group_name=server['group_name'], fqdn=server['reported_fqdn'],
                                                   connecting_fqdn=server['connecting_ip_fqdn'])
        elif isinstance(groups, str):
            url_group_member = url_cp + groups
            logging.info("Calling get_cp method using this url: %s", str(url_group_member))
            response = do_get_cp(url_group_member, access_type, filen)
            logging.info("Response obtained from get_cp method call: %s", str(response))
            for server in response['servers']:
                logging.info("Adding info about this server to 'servers' list: %s", str(server['id']))
                servers[server['id']] = Server(url=server['url'], id=server['id'], hostname=server['hostname'],
                                               ip_address=server['interfaces'][0]['ip_address'],
                                               connecting_ip=server['connecting_ip_address'],
                                               group_name=server['group_name'], fqdn=server['reported_fqdn'],
                                               connecting_fqdn=server['connecting_ip_fqdn'])
    logging.info("Finished adding all servers from all groups to servers list, will now be returned")
    logging.info("Finished get_all_servers method call")
    logging.info("Final list of servers: %s", str(servers))
    return servers


def do_get_cp(url='', access_type='R', filen=''):
    """
    :param url: What url to execute
    :param access_token: Access token to use. In case it is empty will generate the same.
    :return: returns the response.
    """
    global access_token
    logging.info("In get_cp method call")
    logging.info("Checking access_token validity, access_token= %s", str(access_token))
    if not url:
        url = 'https://api.cloudpassage.com/v1/servers?state=active'
    if not access_token:
        logging.info("access_token is empty, trying to retrieve 'Read' token using 'get_token' method call")
        do_get_token(access_type, filen)
    logging.info("access token obtained: %s", str(access_token))
    headers = {"Content-Type": "application/json;charset=UTF=8", "Cache-Control": "no-store", "Pragma": "no-cache",
               "Authorization": "Bearer " + access_token}
    logging.info("Header information for making a get_cp request to cloudpassage: %s", str(headers))
    logging.info("URL being hit: %s", str(url))
    response_cp = requests.get(url, headers=headers)
    logging.info("Status code of response: %s", str(response_cp.status_code))
    if response_cp.status_code == 200:
        logging.info("Request went through correctly, success")
        jsonobj = json.loads(response_cp.text)
        logging.info("Converted response text to json object, returning: %s", str(jsonobj))
        logging.info("Finished get_cp method call")
        logging.info("JSON obj from get_cp request: %s", str(jsonobj))
        return jsonobj
    else:
        logging.info("Request failed, %s", str(response_cp.status_code))
        logging.info("Finished get_cp method call")
        logging.info("Status code returned from get_cp method call: %s", str(response_cp.status_code))
        return response_cp.status_code


def cloudpassage_authentication(clientid, secretkey):
    """
    :param clientid: Client id of authentication
    :param secretkey: Secret key of authentication
    :return: Access token
    """
    logging.info("In cloudpassage_authentication method call")
    logging.info("Arguments passed to this method call: %s and: %s", str(clientid), str(secretkey))
    url_authentication = "https://api.cloudpassage.com/oauth/access_token?grant_type=client_credentials"
    logging.info("URL being used to authenticate:, %s", str(url_authentication))
    auth_string = clientid + ":" + secretkey
    logging.info("auth_string value: %s", str(auth_string))
    authorizationtoken = base64.b64encode(auth_string.encode('UTF-8'))
    logging.info("Authorization token generated after base64 encoding: %s", str(authorizationtoken))
    authorization = "Basic " + str(authorizationtoken)[2:-1]
    logging.info("Final authorization string: %s", str(authorization))
    headers = {"Content-Type": "application/xml;charset=UTF=8", "Cache-Control": "no-store", "Pragma": "no-cache",
               "Authorization": authorization}
    logging.info("Header information: %s", str(headers))
    auth_response = requests.post(url_authentication, headers=headers)
    logging.info("authorization response obtained: %s", str(auth_response))
    logging.info("Status code in authorization response obtained: %s", str(auth_response.status_code))
    if auth_response.status_code == 200:
        logging.info("Authorization successful")
        r = json.loads(auth_response.text)
        logging.info("response text in json format: %s", str(r))
        access_token = r.get("access_token")
        logging.info("Access_token in response: %s", str(access_token))
        logging.info("Finished cloudpassage_authentication method call")
        logging.info("Access token: %s", str(access_token))
        return access_token
    else:
        logging.info("Finished cloudpassage_authentication method call")
        logging.info("Cannot authenticate user, Check your credentials")
        logging.info("Response code obtained: %s", str(auth_response.status_code))
        sys.exit(2)


def do_get_token(access_type='R', filen=''):
    """
    Used for creating a access token
    :param type: R/W read or write
    :param filen: Read the token from where.
    :return:
    """
    global access_token
    logging.info("In get_token method call")
    logging.info("Arguments info, type: %s and filename (that has credentials info): %s", str(access_type),
                 str(filen))
    config = json.loads(open(filen, 'r').read())
    logging.info("Configuration in token file: %s", str(config))
    clientid = ''
    secretkey = ''
    if access_type == 'R':
        logging.info("In READ mode")
        clientid = config['READ']['clientid']
        secretkey = config['READ']['secretkey']
    elif access_type == 'W':
        logging.info("In READ/WRITE mode")
        clientid = config['WRITE']['clientid']
        secretkey = config['WRITE']['secretkey']

    logging.info("Client ID being used: %s and secret key being used: %s", str(clientid), str(secretkey))
    logging.info("Finished get_token method call")
    access_token = cloudpassage_authentication(clientid, secretkey)


def do_move_server(moveservers, groupid, log):
    """
    :param moveservers: Which servers to move
    :param groupid: Location to move it to
    :param access_token: Access token for the user
    :param log: Log where to write it.
    """
    global access_token
    logging.info("In move_server method call")
    logging.info("Arguments info: ")
    logging.info("Move servers: %s", str(moveservers))
    logging.info("Group ID: %s", str(groupid))
    logging.info("Access token: %s", str(access_token))
    logging.info("Log: %s", str(log))
    payload = {"server": {"group_id": groupid}}
    logging.info("Payload info: %s", str(payload))
    tokenheader = {"Authorization": 'Bearer ' + access_token, "Content-type": "application/json",
                   "Accept": "text/plain"}
    logging.info("Token header information: %s", str(tokenheader))
    for server in moveservers:
        logging.info("Server name (in moveservers list: %s)", str(server))
        response_cp = requests.put(server, headers=tokenheader, data=json.dumps(payload))
        logging.info("Server: %s Moved with code: %s", str(server), str(response_cp.status_code))
        logging.info("Server: %s Moved with code : %s", str(server), str(response_cp.status_code))
        if response_cp.status_code == 401:
            logging.info("Failed in moving servers, trying with write access token")
            access_token = do_get_token('W')
            logging.info("Access token being used: %s", str(access_token))
            tokenheader = {"Authorization": 'Bearer ' + access_token, "Content-type": "application/json",
                           "Accept": "text/plain"}
            logging.info("token header information: %s", str(tokenheader))
            response_cp = requests.put(server, headers=tokenheader, data=json.dumps(payload))
            logging.info("Response obtained: %s", str(response_cp))
            logging.info("Status code in resposne: %s", str(response_cp.status_code))
            logging.info("Finished move_server method call")
            exit()


def do_move_server_threaded(moveservers, groupid, threads):
    """
    :param moveservers: server to be moved
    :param groupid: Final destination to move it to.
    :param threads: Move it how many threads.
    """
    logging.info("In move_server_threaded method call")
    logging.info("Arguments info: ")
    logging.info("Move servers: %s", str(moveservers))
    logging.info("Group ID: %s", str(groupid))
    logging.info("Access token: %s", str(threads))
    filename = '..//..//CloudPassage_data//' + time.strftime('%Y-%m-%d-%H-%M-%S-') + "log_fromoveserver.txt"
    log = open(filename, 'w')
    logging.info("Calling get_token method")
    access_token = do_get_token('W')
    logging.info("Access token being used: %s", str(access_token))
    start = 0
    max = int(len(moveservers) / threads)
    running_thread = []
    for thread in range(0, threads):
        logging.info("Thread number: %s", str(thread))
        try:
            logging.info("In try block")
            slice = moveservers[start: max]
            logging.info("Slice of servers being used: %s", str(slice))
            moveservers = moveservers[max:]
            logging.info("Moveservers list: %s", str(moveservers))
            t = Thread(target=do_move_server, args=(slice, groupid, access_token, log,))
            logging.info("Thread: %s", str(t))
            t.start()
            logging.info("Thread: %s is being appended to running_threads list", str(t))
            running_thread.append(t)
        except Exception:
            logging.info("Got exception got thread: %s", str(t))
            import traceback

            print(traceback.format_exc())
            logging.error("Error info: %s", str(traceback.format_exc()))
    t = Thread(target=do_move_server, args=(moveservers[start:], groupid, access_token, log))
    logging.info("Out of 'for' loop, now initializing new thread: %s", str(t))
    t.start()
    logging.info("Thread: %s is being appended to running_threads list", str(t))
    running_thread.append(t)

    for t in running_thread:
        logging.info("Thread: %s in running_threads list is being joined together", str(t))
        t.join()


if __name__ == '__main__':
    do_get_token('R')
    print(access_token)
    response = do_get_cp("https://api.cloudpassage.com/v1/servers?state=active", 'R', 'token')
    print(response)
