import json
import os
import re
import subprocess

TOKEN_PATH = os.path.join(os.path.expanduser('~'), '.bwsession')
token_pattern = re.compile(r'.*BW_SESSION="(?P<token>.+)".*')


class VaultLockedException(Exception):
    pass


class FaultyPasswordInput(Exception):
    pass


def getSessionToken():
    session_token = None

    if os.path.isfile(TOKEN_PATH):
        with open(TOKEN_PATH) as f:
            session_token = f.read()
    else:
        session_token = login()

    return session_token


def login():
    process = subprocess.run(['bw', 'unlock'], stdout=subprocess.PIPE)

    match = token_pattern.search(process.stdout.decode('utf-8'))

    if match:
        token = match.group('token')

        with open(TOKEN_PATH, 'w') as f:
            f.write(token)

        return token

    os.remove(TOKEN_PATH)
    raise FaultyPasswordInput()


def syncVault(session_token):
    command = ['bw', 'sync', '--session', session_token]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if process.returncode != 0:
        raise VaultLockedException


def getPassword(session_token, search_string):
    try:
        syncVault(session_token)
    except VaultLockedException:
        session_token = login()
        syncVault(session_token)

    command = [
        'bw', 'list', 'items',
        '--session', session_token,
        '--search', search_string
    ]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if process.returncode == 0:
        items = json.loads(process.stdout)

        if len(items) > 0:
            if len(items) > 1:
                print(f'Warning: found multiple matches. Selecting {items[0]["name"]}')

            print(f'user: {items[0]["login"]["username"]}')
            return items[0]['login']['password']
        else:
            raise IndexError('No matches found')

    raise VaultLockedException()
