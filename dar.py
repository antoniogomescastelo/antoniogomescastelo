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
def get_asset_name(args=None, asset_uuid=None):
    try:
        return args.names[asset_uuid]
    except Exception as e:
        pass

    try:
        response = args.session.get(args.url + '/rest/2.0/assets/' + asset_uuid)

        args.logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        args.names[asset_uuid] = response.json()['name']

        return response.json()['name']

    except Exception as e:
        # if classification instead
        try:
            response = args.session.get(args.url + '/rest/catalog/1.0/dataClassification/classifications/' + asset_uuid)

            args.logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

            args.names[asset_uuid] = response.json()['name']

            return response.json()['name']

        except Exception as e:
            return None



# get asset type name for uuid
def get_assettype_name(args=None, type_uuid=None, asset_uuid=None):
    try:
        return args.names[type_uuid]

    except Exception as e:
        pass

    try:
        response = args.session.get(args.url + '/rest/2.0/assetTypes/'+type_uuid)

        args.logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        args.names[type_uuid] = response.json()['name']

        return response.json()['name']

    except Exception as e:
        # if classification instead
        try:
            response = args.session.get(args.url + '/rest/catalog/1.0/dataClassification/classifications/' + asset_uuid)

            args.logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

            args.names[type_uuid] = response.json()['resourceType']

            return response.json()['resourceType']

        except Exception as e:
            return None



# get protect standards and acccess rules
def get_policies(args=None):
    policies = {}

    allItems = ['type', 'id', 'name', 'groups', 'asset', 'assets', 'masking', 'maskings', 'grantAccess']

    try:
        response = args.session.get(args.url + '/rest/protect/v1/policies')

        args.logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        policies = [dict(filter(lambda i: (i[0] in allItems), policy.items())) for policy in response.json()['results']]

    except Exception as e:
        pass

    return policies



# get group names from protect policy groups
def get_policies_dataframe_groups(args, policies_df=None):
    policies_df['group name'] = policies_df.groups.apply(lambda x: x.get('name'))

    policies_df.drop(['groups'], axis=1, inplace=True)

    return policies_df



# get assets details from protect policy scope assets
def get_policies_dataframe_assets(args=None, policies_df=None):
    policies_df['assets'] = np.where(policies_df.assets.isnull(), policies_df['asset'], policies_df['assets'])

    policies_df['scope asset id'] = policies_df.assets.apply(lambda x: x.get('id'))

    policies_df['scope asset type'] = policies_df.assets.apply(lambda x: x.get('type'))

    policies_df['scope asset name'] = policies_df.assets.apply(lambda x: get_asset_name(args, x.get('id')))

    policies_df['scope asset type name'] = policies_df.assets.apply(lambda x: get_assettype_name(args, x.get('type'), x.get('id')))

    policies_df.drop(['asset', 'assets'], axis=1, inplace=True)

    return policies_df



# get masking asset details from protect policy maskings
def get_policies_dataframe_maskings(args=None, policies_df=None):
    policies_df['maskings'] = np.where(policies_df.maskings.isnull(), policies_df['masking'], policies_df['maskings']) 

    policies_df['masking asset id'] = policies_df.maskings.apply(lambda x: x.get('id'))

    policies_df['masking asset type'] = policies_df.maskings.apply(lambda x: x.get('type'))

    policies_df['masking asset name'] = policies_df.maskings.apply(lambda x: get_asset_name(args, x.get('id')))

    policies_df['masking asset type name'] = policies_df.maskings.apply(lambda x: get_assettype_name(args, x.get('type'), x.get('id')))

    policies_df['masking method'] = policies_df.maskings.apply(lambda x:  x.get('method'))

    # copy from scope asset if standard
    policies_df['masking asset id'] = np.where(policies_df['masking asset id'].isnull(), policies_df['scope asset id'], policies_df['masking asset id']) 

    policies_df['masking asset type'] = np.where(policies_df['masking asset type'].isnull(), policies_df['scope asset type'], policies_df['masking asset type']) 
    
    policies_df['masking asset name'] = np.where(policies_df['masking asset name'].isnull(), policies_df['scope asset name'], policies_df['masking asset name']) 
    
    policies_df['masking asset type name'] = np.where(policies_df['masking asset type name'].isnull(), policies_df['scope asset type name'], policies_df['masking asset type name']) 

    policies_df.drop(['masking', 'maskings'], axis=1, inplace=True)

    return policies_df



# get protect standards and data access rules 
def get_policies_dataframe(args=None, policies=None):
    policies_df = pd.DataFrame(policies).explode('groups').explode('assets').explode('maskings')

    policies_df = get_policies_dataframe_groups(args, policies_df)

    policies_df = get_policies_dataframe_assets(args, policies_df)

    policies_df = get_policies_dataframe_maskings(args, policies_df)

    policies_df.drop(['id', 'type', 'name'], axis=1, inplace=True)

    policies_df.drop_duplicates(inplace=True)

    return policies_df



# get tags and column masking functions names 
def get_functions_dataframe_maskings(args=None, functions_df=None):    
    schemaName = args.catalog + '.' + args.schema

    functions_df['masking asset name'] = functions_df['masking asset name'].str.replace('[ .]', '', regex=True)

    functions_df['masking asset type name'] = functions_df['masking asset type name'].map({'Classification':'DataConcept', 'Data Category':'DataCategory'})

    functions_df = functions_df.assign(tag=lambda x: x['masking asset type name'] + ':' + x['masking asset name'])

    functions_df = functions_df.assign(function=lambda x: schemaName + '.' + x['masking asset type name'] + '_' + x['masking asset name'])
    
    functions_df.drop(['masking asset name'], axis=1, inplace=True)

    return functions_df



# get tags and column masking functions from policies
def get_functions_dataframe(args=None, policies_df=None):
    functions_df = policies_df.copy(deep=True)

    functions_df.drop(['scope asset id', 'scope asset name', 'scope asset type', 'scope asset type name', 'masking asset id', 'masking asset type', 'grantAccess'], axis=1, inplace=True)

    functions_df.drop_duplicates(inplace=True)

    functions_df = get_functions_dataframe_maskings(args, functions_df)

    functions_df.drop(['masking asset type name'], axis=1, inplace=True)
    
    return functions_df



# drop column masking functions no longer active
def drop_masking_functions(args=None, functions_df=None):
    schemaName = args.catalog+'.'+args.schema

    try:    
        session = requests.Session()

        session.auth = BearerAuth(args.token)

        payload = {
            'warehouse_id': args.warehouse,
            'statement': "SHOW USER FUNCTIONS IN sbi_template_unitycatalog;" 
        }

        args.logger.debug('payload:\n%s', payload)

        response = session.post(args.host + '/api/2.0/sql/statements', json=payload)

        args.logger.debug('response:\n%s', response.json())

        before_df = pd.DataFrame(response.json()['result']['data_array'], columns=['function'])

        tobedeleted_df = before_df.merge(pd.DataFrame(functions_df['function'].str.lower()), how='left', indicator=True)
        
        tobedeleted_df = tobedeleted_df[tobedeleted_df['_merge'] == 'left_only']

        tobedeleted_df.drop(['_merge'], axis=1, inplace=True)

        for index, row in tobedeleted_df.iterrows():
            if row[0] == schemaName + '.protect': #reserved
                continue

            try:
                payload = {
                    'warehouse_id': args.warehouse,
                    'statement': 'SELECT DISTINCT a.catalog, a.schema, a.table, a.column FROM {}.tag_assignments a, {}.tag_protection_methods b WHERE lower(b.function) = \'{}\' AND lower(a.tag) = lower(b.tag)'.format(schemaName, schemaName, row[0])
                }

                args.logger.debug('payload:\n%s', payload)

                response = session.post(args.host + '/api/2.0/sql/statements', json=payload)

                args.logger.debug('response:\n%s', response.json())

                for c in response.json()['result']['data_array']: 
                    try:
                        tableName = ".".join(c[:3])

                        columnName = c[3]

                        payload = {
                            'warehouse_id': args.warehouse,
                            'statement': 'ALTER TABLE {} ALTER COLUMN {} DROP MASK;'.format(tableName, columnName)
                        }

                        args.logger.debug('payload:\n%s', payload)

                        response = session.post(args.host + '/api/2.0/sql/statements', json=payload)

                        args.logger.debug('response:\n%s', response.json())

                    except Exception as e:
                        continue

                try:
                    payload = {
                        'warehouse_id': args.warehouse,
                        'statement': 'DROP FUNCTION {};'.format(row[0])
                    }

                    args.logger.debug('payload:\n%s', payload)

                    response = session.post(args.host + '/api/2.0/sql/statements', json=payload)

                    args.logger.debug('response:\n%s', response.json())

                except Exception as e:
                    pass

            except Exception as e:
                pass
    
    except Exception as e:
        pass



# get create or replace masking functions statement
def get_create_functions_commands(args=None, functions_df=None):
    schemaName = args.catalog + '.' + args.schema

    statement = ''

    statements = [] #['TRUNCATE TABLE {}.tag_protection_methods;'.format(schemaName)]

    lastTag = None
    lastFunction = None
    for index, row in functions_df.sort_values(by=['function']).iterrows():
        if row['function'] != lastFunction:
            if len(statement):
                statement = '{}\nELSE value\nEND;\n'.format(statement)

                statements.append(statement)

                #statements.append('INSERT INTO {}.tag_protection_methods VALUES (\'{}\', \'{}\');'.format(schemaName, lastTag, lastFunction))

                statement = ''

            statement = '{}\nCREATE OR REPLACE FUNCTION {}(value STRING, method STRING)\nRETURNS STRING\nRETURN CASE'.format(statement, row['function'])
            
            lastTag = row['tag']
            lastFunction = row['function']

        statement = '{}\nWHEN IS_ACCOUNT_GROUP_MEMBER(\'{}\') THEN {}.protect(value, \'{}\')'.format(statement, row['group name'], schemaName,row['masking method'])

    if len(statement):
        statement = '{}\nELSE value\nEND;\n'.format(statement)
        
        statements.append(statement)

        #statements.append('INSERT INTO {}.tag_protection_methods VALUES (\'{}\', \'{}\');'.format(schemaName, lastTag, lastFunction))

        statement = ''

    return statements



# create or replace column masking functions
def update_masking_functions(args=None, functions_df=None):
    session = requests.Session()

    session.auth = BearerAuth(args.token)

    for statement in get_create_functions_commands(args, functions_df):
        payload = {
            'warehouse_id': args.warehouse,
            'statement': statement
        }

        args.logger.debug('payload:\n%s', payload)

        response = session.post(args.host + '/api/2.0/sql/statements', json=payload)

        args.logger.debug('response:\n%s', response.json())



# run
def run(argv=None):
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
        '--db-catalog',
        dest='catalog',
        required=True,
        help='databricks catalog name')

    parser.add_argument(
        '--db-schema',
        dest='schema',
        required=True,
        help='databricks schema name')

    parser.add_argument(
        '--logger',
        dest='logger',
        required=False,
        type=int,
        help='logger logging level')

    args, options= parser.parse_known_args(argv)

    args.logger = get_logger(int(args.logger)) if args.logger is not None else get_logger(logging.INFO)

    args.logger.info("got args")        

    # names
    args.names= {}

    # get session
    args.session = get_session(args=args)

    # get policies
    policies = get_policies(args=args)

    args.logger.info("got policies")        

    policies_df = get_policies_dataframe(args=args, policies=policies)

    args.logger.info("got policies dataframe")        

    # get masking functions
    functions_df = get_functions_dataframe(args=args, policies_df=policies_df)

    args.logger.info("got mask functions from policies")        
    
    # drop old masking functions
    drop_masking_functions(args=args, functions_df=functions_df)

    args.logger.info("dropped column masking functions")        

    # update all masking functions
    update_masking_functions(args=args, functions_df=functions_df)

    args.logger.info("updated column masking functions")        

    # store all masking functions
    functions_sdf=spark.createDataFrame(functions_df[['tag','function']].sort_values(by=['tag']))
   
    functions_sdf.write.mode("overwrite").saveAsTable("main.sbi_template_unitycatalog.tag_protection_methods")

    args.logger.info("persist column masking functions")        

    # apply all masking functions
    #apply_masking_functions(args=args, functions_df=functions_df)

    #args.logger.debug("applied column masking functions")        

    # drop tag assignments dupps
    assignments_sdf = sqlContext.sql("SELECT DISTINCT * FROM main.sbi_template_unitycatalog.tag_assignments") 

    assignments_sdf.write.mode("overwrite").saveAsTable("main.sbi_template_unitycatalog.tag_assignments")

    args.logger.info("dropped duplicate tag assignments")        

    args.logger.info("done")     
    
    return policies_df, functions_df 