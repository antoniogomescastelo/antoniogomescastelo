import sys
import json 
import logging
import argparse

import requests
from requests.auth import HTTPBasicAuth

import numpy as np
import pandas as pd


# bearer auth
class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r



# get logger
def get_logger(level=logging.INFO):
    logger = logging.getLogger()

    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)

    formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s ')

    handler.setFormatter(formatter)

    logger.handlers = [handler]

    return logger



# get session auth
def get_session(args=None):
    session = requests.Session()

    session.auth = HTTPBasicAuth(args.username, args.password)

    return session



# get asset name for uuid
def get_asset_name(url=None, session=None, logger=None, uuid=None, names=None):
    try:
        return names[uuid]

    except Exception as e:
        logger.debug('ignoring: %s', e)

    try:
        response = session.get(url + '/rest/2.0/assets/' + uuid)

        logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        return response.json()['name']

    except Exception as e:
        logger.debug('ignoring: %s', e)

        # if classification
        try:
            response = session.get(url + '/rest/catalog/1.0/dataClassification/classifications/' + uuid)

            logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

            names[uuid] = response.json()['name']

            return response.json()['name']

        except Exception as e:
            logger.debug('ignoring: %s', e)

            return None



# get asset type name for uuid
def get_assettype_name(url=None, session=None, logger=None, type_uuid=None, asset_uuid=None, names=None):
    try:
        return names[type_uuid]

    except Exception as e:
        logger.debug('ignoring: %s', e)

    try:
        response = session.get(url + '/rest/2.0/assetTypes/'+type_uuid)

        logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        names[type_uuid] = response.json()['name']

        return response.json()['name']

    except Exception as e:
        logger.debug('ignoring: %s', e)
        
        # if classification
        try:
            response = session.get(url + '/rest/catalog/1.0/dataClassification/classifications/' + asset_uuid)

            logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

            names[type_uuid] = response.json()['resourceType']

            return response.json()['resourceType']

        except Exception as e:
            logger.debug('ignoring: %s', e)

            return None



# get protect standards and acccess rules
def get_policies(url=None, session=None, logger=None):
    policies = {}

    allItems = ['type', 'id', 'name', 'groups', 'asset', 'assets', 'masking', 'maskings', 'grantAccess']

    try:
        response = session.get(url + '/rest/protect/v1/policies')

        logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        policies = [dict(filter(lambda i: (i[0] in allItems), policy.items())) for policy in response.json()['results']]

    except Exception as e:
        logger.debug('ignoring: %s', e)

    return policies



# get group names, drop dict
def get_policies_groups_transformed(url=None, session=None, logger=None, policies_df=None, names=None):
    
    policies_df['group name'] = policies_df.groups.apply(lambda x: x.get('name'))

    policies_df.drop(['groups'], axis=1, inplace=True)

    return policies_df



# get scope assets, drop dict
def get_policies_assets_transformed(url=None, session=None, logger=None, policies_df=None, names=None):
    
    policies_df['assets'] = np.where(policies_df.assets.isnull(), policies_df['asset'], policies_df['assets'])

    policies_df['scope asset id'] = policies_df.assets.apply(lambda x: x.get('id'))

    policies_df['scope asset type'] = policies_df.assets.apply(lambda x: x.get('type'))

    policies_df['scope asset name'] = policies_df.assets.apply(lambda x: get_asset_name(url, session, logger, x.get('id'), names))

    policies_df['scope asset type name'] = policies_df.assets.apply(lambda x: get_assettype_name(url, session, logger, x.get('type'), x.get('id'), names))

    policies_df.drop(['asset', 'assets'], axis=1, inplace=True)

    return policies_df



# get masking assets, drop dict
def get_policies_maskings_transformed(url=None, session=None, logger=None, policies_df=None, names=None):
        
    policies_df['maskings'] = np.where(policies_df.maskings.isnull(), policies_df['masking'], policies_df['maskings']) 

    policies_df['masking asset id'] = policies_df.maskings.apply(lambda x: x.get('id'))

    policies_df['masking asset type'] = policies_df.maskings.apply(lambda x: x.get('type'))

    policies_df['masking asset name'] = policies_df.maskings.apply(lambda x: get_asset_name(url, session, logger, x.get('id'), names))

    policies_df['masking asset type name'] = policies_df.maskings.apply(lambda x: get_assettype_name(url, session, logger, x.get('type'), x.get('id'), names))

    policies_df['masking method'] = policies_df.maskings.apply(lambda x:  x.get('method'))

    # standard masking asset is null, copy
    policies_df['masking asset id'] = np.where(policies_df['masking asset id'].isnull(), policies_df['scope asset id'], policies_df['masking asset id']) 

    policies_df['masking asset type'] = np.where(policies_df['masking asset type'].isnull(), policies_df['scope asset type'], policies_df['masking asset type']) 
    
    policies_df['masking asset name'] = np.where(policies_df['masking asset name'].isnull(), policies_df['scope asset name'], policies_df['masking asset name']) 
    
    policies_df['masking asset type name'] = np.where(policies_df['masking asset type name'].isnull(), policies_df['scope asset type name'], policies_df['masking asset type name']) 

    policies_df.drop(['masking', 'maskings'], axis=1, inplace=True)

    return policies_df



# get standards and access rules transformed
def get_policies_transformed(url=None, session=None, logger=None, policies=None, names=None):
    policies_df = pd.DataFrame(policies).explode('groups').explode('assets').explode('maskings')

    policies_df = get_policies_groups_transformed(url, session, logger, policies_df, names)

    policies_df = get_policies_assets_transformed(url, session, logger, policies_df, names)

    policies_df = get_policies_maskings_transformed(url, session, logger, policies_df, names)

    policies_df.drop(['id', 'type', 'name'], axis=1, inplace=True)

    policies_df.drop_duplicates(inplace=True)

    return policies_df



# get column mansking functions transformed
def get_functions_masking_transformed(functions_df=None):    
    functions_df['masking asset name'] = functions_df['masking asset name'].str.replace('[ .]', '', regex=True)

    functions_df['masking asset type name'] = functions_df['masking asset type name'].map({'Classification':'DataConcept', 'Data Category':'DataCategory'})

    functions_df = functions_df.assign(tag=lambda x: x['masking asset type name'] + ':' + x['masking asset name'])

    functions_df = functions_df.assign(function=lambda x: x['masking asset type name'] + '_' + x['masking asset name'])
    
    functions_df.rename(columns={"masking asset name": "parameter"}, inplace=True)

    return functions_df



# get column masking functions processed
def get_functions_transformed(policies_df=None):
    functions_df = policies_df.copy(deep=True)

    functions_df.drop(['scope asset id', 'scope asset name', 'scope asset type', 'scope asset type name', 'masking asset id', 'masking asset type', 'grantAccess'], axis=1, inplace=True)

    functions_df.drop_duplicates(inplace=True)

    functions_df = get_functions_masking_transformed(functions_df)

    functions_df.drop(['masking asset type name'], axis=1, inplace=True)
    
    return functions_df


# get column masking functions statements
def get_functions_statements(functions_df=None):
    statement = ''
    statements = []

    last = None
    for index, row in functions_df.sort_values(by=['function']).iterrows():
        if row['function'] != last:
            if len(statement):
                statement = '{}\nELSE value\nEND;\n'.format(statement)
                statements.append(statement)
                statement = ''

            statement = '{}\nCREATE OR REPLACE FUNCTION main.sbi_template_unitycatalog.{}(value STRING, method STRING)\nRETURNS STRING\nRETURN CASE'.format(statement, row['function'])
            
            last = row['function']

        statement = '{}\nWHEN IS_ACCOUNT_GROUP_MEMBER(\'{}\') THEN main.sbi_template_unitycatalog.protect(value, \'{}\')'.format(statement, row['group name'], row['masking method'])

    if len(statement):
        statement = '{}\nELSE value\nEND;\n'.format(statement)
        statements.append(statement)

    return statements
            

# create column masking functions
def create_masking_functions(host=None, token=None, warehouse=None, logger=None, functions_df=None):
    session = requests.Session()

    session.auth = BearerAuth(token)

    for statement in get_functions_statements(functions_df):
        payload = {
            'warehouse_id': warehouse,
            'statement': statement
        }

        response = session.post(host + '/api/2.0/sql/statements', json=payload)

        logger.debug('response:\n%s', response.json())


# run
def run(argv=None):
    logger = get_logger(logging.INFO)

    logger.debug("got logger")

    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        '--url',
        dest='url',
        required=True,
        help='collibra instance url')

    parser.add_argument(
        '--username',
        dest='username',
        required=True,
        help='collibra instance username')

    parser.add_argument(
        '--password',
        dest='password',
        required=True,
        help='collibra instance password')

    parser.add_argument(
        '--dbc-host',
        dest='host',
        required=True,
        help='databricks workspace url')

    parser.add_argument(
        '--dbc-token',
        dest='token',
        required=True,
        help='databricks workspace token')

    parser.add_argument(
        '--db-warehouse',
        dest='warehouse',
        required=True,
        help='databricks warehouse id')

    parser.add_argument(
        '--logger',
        dest='logger',
        required=False,
        type=int,
        help='logger logging level')

    args, options= parser.parse_known_args(argv)

    if args.logger is not None:
        logger = get_logger(args.logger)

    logger.debug("parsed known args")        

    names= {}

    session = get_session(args)

    # get policies
    policies = get_policies(url=args.url, session=session, logger=logger)

    logger.debug("got policies")        

    policies_df = get_policies_transformed(url=args.url, session=session, logger=logger, policies=policies, names=names)

    logger.debug("got policies transformed")        
    

    # get masking functions
    functions_df = get_functions_transformed(policies_df)

    logger.debug("gor functions from policies")        

    # create masking functions
    create_masking_functions(host=args.host, token=args.token, warehouse=args.warehouse, logger=logger, functions_df=functions_df)

    return policies_df, functions_df 
