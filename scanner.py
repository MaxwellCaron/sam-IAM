#!/usr/bin/env python3

import json
import args as argsmod
import awsaccount
import boto3
import botocore.exceptions

GROUPS = []

###########################################
# ------------) Stylization (-------------#
###########################################

# https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/builder/linpeas_parts/linpeas_base.sh
# ╠ ╣ ═ ╔ ╗ ╚ ╝ ║
RED = '\033[91m'
GREEN = '\033[0;39;32m'
GRAY = '\033[1;30m'
YELLOW = '\033[33m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_title(text):
    title_len = len(text)
    max_title_len = 100
    side_len = int((max_title_len - title_len) / 2)

    left = f'{CYAN}{"═" * side_len}╣{RESET}'
    right = f'{CYAN}╠{"═" * side_len}{RESET}'

    top = f'{CYAN}{" " * (len(left) - 10)}╔{"═" * (len(text) + 2)}╗\n'
    bottom = f'\n{CYAN}{" " * (len(left) - 10)}╚{"═" * (len(text) + 2)}╝'

    print(f'{top}{left} {GREEN}{BOLD}{text} {right}{bottom}')


def print_title1(text):
    print(f'\n{CYAN}╔══════════╣ {MAGENTA}{BOLD}{text}{RESET}')


def print_title2(text):
    print(f'{CYAN}║\n╠═════╣ {YELLOW}{BOLD}{text}{RESET}')


def print_title3(text):
    print(f'{CYAN}║\n╠══╣ {GRAY}{text}{RESET}')


def print_info(text, border=True):
    if border:
        print(f'{CYAN}║\n║ {YELLOW}[+] {GREEN}{text}{RESET}')
    else:
        print(f'\n{YELLOW}[+] {GREEN}{text}{RESET}')


def print_data(text):
    data = (f'{CYAN}║{RESET} ' + str(json.dumps(text, indent=4, default=str))).split('\n')
    print(f'\n{CYAN}║{RESET} '.join(data))


def print_error():
    print(f'{RED}[-] Access Denied{RESET}')


###########################################
# ---------------) General (--------------#
###########################################

def handle_client_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError:
            print_error()

    return wrapper


@handle_client_error
def get_caller_identity(session):
    resp = session.client("sts").get_caller_identity()
    return resp["Arn"].split('/')[-1]


@handle_client_error
def get_policy(session, policy_arn):
    print_title3(f'Get-Policy')

    resp = session.client("iam").get_policy(PolicyArn=policy_arn)
    print_data(resp['Policy'])
    get_policy_version(session, policy_arn, resp['Policy']['DefaultVersionId'])


@handle_client_error
def get_policy_version(session, policy_arn, version_id):
    print_title3('Get-Policy-Version')

    resp = session.client("iam").get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    policies = resp['PolicyVersion']['Document']['Statement']

    for policy in policies:
        print_data(policy)


# Attached
@handle_client_error
def get_attached_policies(session: boto3.Session, policy_type: str, name: str):
    client = session.client("iam")

    if policy_type == 'user':
        resp = client.list_attached_user_policies(UserName=name)
    elif policy_type == 'group':
        resp = client.list_attached_group_policies(GroupName=name)
    else:
        resp = client.list_attached_role_policies(RoleName=name)

    policies = resp.get('AttachedPolicies', [])
    num_policies = len(policies)

    if num_policies == 1:
        print_info(f'Found {num_policies} Attached Policy')
    else:
        print_info(f'Found {num_policies} Attached Policies')

    for i, policy in enumerate(policies, 1):
        print_title2(f'[{i}] {policy["PolicyName"]} ({policy["PolicyArn"]})')
        get_policy(session, policy['PolicyArn'])


# Inline
@handle_client_error
def get_inline_policies(session: boto3.Session, policy_type: str, name: str):
    client = session.client("iam")

    if policy_type == 'user':
        resp = client.list_user_policies(UserName=name)
        policy_getter = get_user_policy
    elif policy_type == 'group':
        resp = client.list_group_policies(GroupName=name)
        policy_getter = get_group_policy
    else:
        resp = client.list_role_policies(RoleName=name)
        policy_getter = get_role_policy

    policies = resp.get('PolicyNames', [])
    num_policies = len(policies)

    if num_policies == 1:
        print_info(f'Found {num_policies} Inline Policy')
    else:
        print_info(f'Found {num_policies} Inline Policies')

    for i, policy_name in enumerate(policies, 1):
        print_title2(f'[{i}] {policy_name}')
        policy_getter(session, name, policy_name)


###########################################
# ---------------) Users (----------------#
###########################################

def enum_user_policies(session, username):
    print_title("User")

    print_title1('Attached')
    get_attached_policies(session, 'user', username)

    print_title1('Inline')
    get_inline_policies(session, 'user', username)


@handle_client_error
def get_user_policy(session, username, policy_name):
    print_title3('Get-User-Policy')

    resp = session.client("iam").get_user_policy(UserName=username, PolicyName=policy_name)
    resp.popitem()  # Remove "ResponseMetadata"

    print_data(resp["PolicyDocument"])


###########################################
# ---------------) Groups (---------------#
###########################################


@handle_client_error
def enum_groups_for_user(session, username):
    print_title(f'"{username}" Group Memeberships')

    resp = session.client("iam").list_groups_for_user(UserName=username)
    resp.popitem()  # Remove "ResponseMetadata"
    groups = resp['Groups']

    if groups:
        # print_data(groups)

        for group in groups:
            GROUPS.append(group["GroupName"])
            print_title1(f'{group["GroupName"]} ({group["Arn"]})')
            get_attached_policies(session, 'group', group['GroupName'])

            get_inline_policies(session, 'group', group['GroupName'])


@handle_client_error
def enum_group_policies(session):
    print_title('Other Groups')

    resp = session.client("iam").list_groups()
    resp.popitem()  # Remove "ResponseMetadata"
    groups = resp['Groups']

    for group in groups:
        if group["GroupName"] not in GROUPS:
            # Attached
            print_title1(f'{group["GroupName"]} ({group["Arn"]})')
            get_attached_policies(session, 'group', group['GroupName'])

            # Inline
            get_inline_policies(session, 'group', group['GroupName'])


@handle_client_error
def get_group_policy(session, group_name, policy_name):
    print_title3(f'Get-Group-Policy')

    resp = session.client("iam").get_group_policy(GroupName=group_name, PolicyName=policy_name)
    print_data(resp["PolicyDocument"])


###########################################
# ---------------) Roles (----------------#
###########################################

@handle_client_error
def enum_role_policies(session):
    print_title('Roles')

    resp = session.client("iam").list_roles()
    roles = resp['Roles']

    for role in roles:
        if 'AWSServiceRoleFor' not in role['RoleName']:
            print_title1(role["RoleName"])
            print_title3('Get-Role')
            print_data(role)

            get_attached_policies(session, 'role', role['RoleName'])
            get_inline_policies(session, 'role', role['RoleName'])


@handle_client_error
def get_role_policy(session, role_name, policy_name):
    print_title3(f'Get-Role-Policy')

    resp = session.client("iam").get_role_policy(RoleName=role_name, PolicyName=policy_name)
    print_data(resp["PolicyDocument"])


def main():
    args = argsmod.parse_args()

    try:
        account = awsaccount.resolve_aws_account(
            args.profile,
            access_key=args.access_key,
            secret_key=args.secret_key,
            session_token=args.session_token,
            region=args.region,
        )
    except awsaccount.AccountError as e:
        print(f"Error: {e}")
        return

    session = boto3.Session(
        aws_access_key_id=account.access_key,
        aws_secret_access_key=account.secret_key,
        aws_session_token=account.session_token,
        region_name=account.region,
    )

    username = get_caller_identity(session)

    enum_user_policies(session, username)
    enum_groups_for_user(session, username)
    enum_group_policies(session)
    enum_role_policies(session)


if __name__ == "__main__":
    main()
