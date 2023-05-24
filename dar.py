import sys
import json 
import logging
import argparse

import requests
from requests.auth import HTTPBasicAuth
from databricks.sdk.runtime import *

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
    
    formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s ')

    handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)

    logger.handlers = [handler]

    logger.setLevel(level)

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



# get standards and acccess rules
def get_policies(args=None):
    policies = {}

    allItems = ['type', 'id', 'name', 'groups', 'asset', 'assets', 'masking', 'maskings', 'grantAccess', 'rowFilters']

    try:
        response = args.session.get(args.url + '/rest/protect/v1/policies')

        args.logger.debug('response:\n%s', json.dumps(response.json(), indent=2))

        policies = [dict(filter(lambda i: (i[0] in allItems), policy.items())) for policy in response.json()['results']]

    except Exception as e:
        pass

    return policies



# get group names from policy groups
def get_masking_rules_groups(args, protection_rules_df=None):
    protection_rules_df['groupName'] = protection_rules_df.groups.apply(lambda x: x.get('name'))

    protection_rules_df.drop(['groups'], axis=1, inplace=True)

    return protection_rules_df



# get assets details from policy scope assets
def get_masking_rules_assets(args=None, protection_rules_df=None):
    protection_rules_df['assets'] = np.where(protection_rules_df.assets.isnull(), protection_rules_df['asset'], protection_rules_df['assets'])

    protection_rules_df['scopeAssetId'] = protection_rules_df.assets.apply(lambda x: x.get('id'))

    protection_rules_df['scopeAssetType'] = protection_rules_df.assets.apply(lambda x: x.get('type'))

    protection_rules_df['scopeAssetName'] = protection_rules_df.assets.apply(lambda x: get_asset_name(args, x.get('id')))

    protection_rules_df['scopeAssetTypeName'] = protection_rules_df.assets.apply(lambda x: get_assettype_name(args, x.get('type'), x.get('id')))

    protection_rules_df.drop(['asset', 'assets'], axis=1, inplace=True)

    return protection_rules_df



# get masking asset details from policy maskings
def get_masking_rules_maskings(args=None, protection_rules_df=None):
    protection_rules_df['maskings'] = np.where(protection_rules_df.maskings.isnull(), protection_rules_df['masking'], protection_rules_df['maskings']) 

    protection_rules_df['maskingAssetId'] = protection_rules_df.maskings.apply(lambda x: x.get('id'))

    protection_rules_df['maskingAssetType'] = protection_rules_df.maskings.apply(lambda x: x.get('type'))

    protection_rules_df['maskingAssetName'] = protection_rules_df.maskings.apply(lambda x: get_asset_name(args, x.get('id')))

    protection_rules_df['maskingAssetTypeName'] = protection_rules_df.maskings.apply(lambda x: get_assettype_name(args, x.get('type'), x.get('id')))

    protection_rules_df['maskingMethod'] = protection_rules_df.maskings.apply(lambda x:  x.get('method'))

    # copy from scope asset if null
    protection_rules_df['maskingAssetId'] = np.where(protection_rules_df['maskingAssetId'].isnull(), protection_rules_df['scopeAssetId'], protection_rules_df['maskingAssetId']) 

    protection_rules_df['maskingAssetType'] = np.where(protection_rules_df['maskingAssetType'].isnull(), protection_rules_df['scopeAssetType'], protection_rules_df['maskingAssetType']) 
    
    protection_rules_df['maskingAssetName'] = np.where(protection_rules_df['maskingAssetName'].isnull(), protection_rules_df['scopeAssetName'], protection_rules_df['maskingAssetName']) 
    
    protection_rules_df['maskingAssetTypeName'] = np.where(protection_rules_df['maskingAssetTypeName'].isnull(), protection_rules_df['scopeAssetTypeName'], protection_rules_df['maskingAssetTypeName']) 

    protection_rules_df.drop(['masking', 'maskings'], axis=1, inplace=True)

    return protection_rules_df



# get standards and data access rules 
def get_masking_rules(args=None, policies=None):
    protection_rules_df = pd.DataFrame(policies).explode('groups').explode('assets').explode('maskings')

    protection_rules_df = get_masking_rules_groups(args, protection_rules_df)

    protection_rules_df = get_masking_rules_assets(args, protection_rules_df)

    protection_rules_df = get_masking_rules_maskings(args, protection_rules_df)

    protection_rules_df.drop(['id', 'type', 'name'], axis=1, inplace=True)

    return protection_rules_df



# get tags and column masking functions names 
def get_masking_functions_maskings(args=None, masking_functions_df=None):    
    schemaName = args.catalog + '.' + args.schema

    masking_functions_df['maskingAssetName'] = masking_functions_df['maskingAssetName'].str.replace('[ .]', '', regex=True)

    masking_functions_df['maskingAssetTypeName'] = masking_functions_df['maskingAssetTypeName'].map({'Classification':'DataConcept', 'Data Category':'DataCategory'})

    masking_functions_df = masking_functions_df.assign(tag=lambda x: x['maskingAssetTypeName'] + ':' + x['maskingAssetName'])

    masking_functions_df = masking_functions_df.assign(function=lambda x: schemaName + '.' + x['maskingAssetTypeName'].str.lower() + '_' + x['maskingAssetName'].str.lower())
    
    masking_functions_df.drop(['maskingAssetName'], axis=1, inplace=True)

    return masking_functions_df



# get tags and column masking functions from policies
def get_masking_functions(args=None, protection_rules_df=None):
    masking_functions_df = protection_rules_df[['groupName', 'maskingAssetName', 'maskingAssetTypeName', 'maskingMethod']].copy(deep=True)

    masking_functions_df.drop_duplicates(inplace=True)

    masking_functions_df = get_masking_functions_maskings(args, masking_functions_df)

    masking_functions_df.drop(['maskingAssetTypeName'], axis=1, inplace=True)
    
    return masking_functions_df



# drop column masking functions no longer active
def drop_masking_functions(args=None, masking_functions_df=None):
    schemaName = args.catalog+'.'+args.schema

    try:    
        statement = 'SHOW USER FUNCTIONS IN {};'.format(args.schema) 

        args.logger.debug('statement:\n%s', statement)
        
        before_df = sqlContext.sql(statement).toPandas()  
        
        tobedeleted_df = before_df.merge(pd.DataFrame(masking_functions_df['function']), how='left', indicator=True) #.str.lower()
        
        tobedeleted_df = tobedeleted_df[tobedeleted_df['_merge'] == 'left_only']

        tobedeleted_df.drop(['_merge'], axis=1, inplace=True)

        for index, row in tobedeleted_df.iterrows():
            if row[0] == schemaName + '.protect': #reserved
                continue

            try:
                statement = 'SELECT DISTINCT a.catalog, a.schema, a.table, a.column FROM {}.tag_assignments a, {}.tag_masking_functions b WHERE b.function = \'{}\' AND lower(a.tag) = lower(b.tag);'.format(schemaName, schemaName, row[0]) #lower(b.function)

                args.logger.debug('statement:\n%s', statement)
                
                results_df = sqlContext.sql(statement).toPandas()  

                args.logger.debug('response:\n%s', results_df.shape)

                results = results_df.shape[0]>0

                for i, r in results_df.iterrows():
                    try:
                        tableName = ".".join(r[:3])

                        columnName = r[3]

                        statement = 'ALTER TABLE {} ALTER COLUMN {} DROP MASK;'.format(tableName, columnName)

                        args.logger.debug('statement:\n%s', statement)
                
                        results_df = sqlContext.sql(statement).toPandas()

                        args.logger.debug('response:\n%s', results_df.shape)

                    except Exception as e:
                        continue

                if results:
                    try:
                        statement = 'DROP FUNCTION {};'.format(row[0])

                        args.logger.debug('statement:\n%s', statement)
                
                        results_df = sqlContext.sql(statement).toPandas()

                        args.logger.debug('response:\n%s', results_df.shape)

                    except Exception as e:
                        pass

            except Exception as e:
                pass
    
    except Exception as e:
        pass



# get create or replace masking functions statement
def get_create_functions_commands(args=None, masking_functions_df=None):
    schemaName = args.catalog + '.' + args.schema

    statement = ''

    statements = []

    lastFunction = None

    for index, row in masking_functions_df.sort_values(by=['function']).iterrows():
        if row['function'] != lastFunction: # if new funtion
            if lastFunction is not None:    # if not first function
                statements.append('DROP FUNCTION {};'.format(lastFunction))

                statements.append('{} ELSE \'[REDACTED]\' END; '.format(statement))
                #statements.append(sta'{} ELSE {}.protect(value, \'DEFAULT_MASKING\') END; '.format(statement, schemaName)tement)

            # each new function
            statement = 'CREATE OR REPLACE FUNCTION {}(value STRING) RETURNS STRING RETURN CASE'.format(row['function'])
            
            lastFunction = row['function']

        # each protection method
        statement = '{} WHEN IS_ACCOUNT_GROUP_MEMBER(\'{}\') THEN {}.protect(value, \'{}\')'.format(statement, row['groupName'], schemaName,row['maskingMethod'])

    if len(statement): # last statement
        statements.append('DROP FUNCTION {};'.format(lastFunction))

        statements.append('{} ELSE \'[REDACTED]\' END; '.format(statement))
        #statements.append('{} ELSE {}.protect(value, \'DEFAULT_MASKING\') END; '.format(statement, schemaName))

    return statements



# create or replace column masking functions
def update_masking_functions(args=None, masking_functions_df=None):
    for statement in get_create_functions_commands(args, masking_functions_df):
        try:
            args.logger.debug('statement:\n%s', statement)
            
            results_df = sqlContext.sql(statement).toPandas()
            
            args.logger.debug('response:\n%s', results_df.shape)
        
        except Exception as e:
            args.logger.debug('response:\nFAILED')
            pass



def apply_masking_functions(args=None, masking_functions_df=None):
    schemaName = args.catalog+'.'+args.schema
    
    try:    
        statement = 'SELECT DISTINCT a.*, b.function FROM {}.tag_assignments a, {}.tag_masking_functions b WHERE lower(b.tag) = lower(a.tag) ORDER BY b.function DESC;'.format(schemaName, schemaName) 

        args.logger.debug('statement:\n%s', statement)
        
        results_df = sqlContext.sql(statement).toPandas()  

        args.logger.debug('response:\n%s', results_df.shape)

        for index, row in results_df.iterrows():
            try:
                tableName = ".".join(row[:3])

                columnName = row['column']

                statement = 'ALTER TABLE {} ALTER COLUMN {} SET MASK {};'.format(tableName, columnName, row['function'])

                args.logger.debug('statement:\n%s', statement)
        
                results_df = sqlContext.sql(statement).toPandas()

                args.logger.debug('response:\n%s', results_df.shape)

            except Exception as e:
                continue

    except Exception as e:
        args.logger.debug('response:\nFAILED')
        pass



# get row level filters assets
def get_rowlevel_filters_assets(args=None, rowlevel_filters_df=None):
    rowlevel_filters_df['action'] = rowlevel_filters_df.rowFilters.apply(lambda x: x.get('action'))

    rowlevel_filters_df['dataClassification'] = rowlevel_filters_df.rowFilters.apply(lambda x: "DataConcept:" + get_asset_name(args, x.get('dataClassification'))).str.replace('[ .]', '', regex=True)

    rowlevel_filters_df['codeValue'] = rowlevel_filters_df.rowFilters.apply(lambda x: get_asset_name(args, x.get('codeValue')))

    rowlevel_filters_df.drop(['rowFilters'], axis=1, inplace=True)

    return rowlevel_filters_df



# get row level filters  
def get_rowlevel_filters(args=None, protection_rules_df=None):    
    rowlevel_filters_df = protection_rules_df[['rowFilters', 'groupName']].copy(deep=True)

    rowlevel_filters_df = rowlevel_filters_df[rowlevel_filters_df.rowFilters.notnull()]

    rowlevel_filters_df = rowlevel_filters_df[rowlevel_filters_df["rowFilters"].str.len() != 0]

    rowlevel_filters_df = rowlevel_filters_df.explode('rowFilters')

    rowlevel_filters_df = get_rowlevel_filters_assets(args=args, rowlevel_filters_df=rowlevel_filters_df )

    return rowlevel_filters_df



# get table row level filters
def get_table_rowlevel_filters(args=None, rowlevel_filters_df=None):
    schemaName = args.catalog+'.'+args.schema
    
    classifications = ",".join(rowlevel_filters_df['dataClassification'].apply(lambda x: "'"+x.lower()+"'").astype(str).values.tolist())

    results_df = None
    try:    
        statement = 'SELECT DISTINCT * FROM {}.tag_assignments a WHERE lower(a.tag) in ({});'.format(schemaName, classifications)

        args.logger.debug('statement:\n%s', statement)
        
        results_df = sqlContext.sql(statement).toPandas()  

        args.logger.debug('response:\n%s', results_df.shape)

        results_df = results_df.assign(filter=lambda x: schemaName + '.' + x['catalog'] + '_' + x['schema'] + '_' + x['table'])


    except Exception as e:
        args.logger.debug('response:\nFAILED')
        pass

    return results_df



# drop table rowlevel filters no longer active
def drop_table_rowlevel_filters(args=None, table_rowlevel_filters_df=None):
    schemaName = args.catalog+'.'+args.schema

    try:    
        statement = 'SHOW USER FUNCTIONS IN {};'.format(args.schema) 

        args.logger.debug('statement:\n%s', statement)
        
        before_df = sqlContext.sql(statement).toPandas()  
        
        tobedeleted_df = before_df.merge(pd.DataFrame(table_rowlevel_filters_df['filter']), how='left', indicator=True, left_on=['function'], right_on = ['filter']) #.str.lower()

        tobedeleted_df = tobedeleted_df[tobedeleted_df['_merge'] == 'left_only']

        tobedeleted_df.drop(['_merge'], axis=1, inplace=True)
        
        for index, row in tobedeleted_df.iterrows():
            if row[0] == schemaName + '.protect': #reserved
                continue

            try:
                statement = 'SELECT DISTINCT a.catalog, a.schema, a.table FROM {}.row_access_filters a WHERE a.filter = \'{}\';'.format(schemaName, row[0]) 

                args.logger.debug('statement:\n%s', statement)
                
                results_df = sqlContext.sql(statement).toPandas()  

                args.logger.debug('response:\n%s', results_df.shape)

                results = results_df.shape[0]>0

                for i, r in results_df.iterrows():
                    try:
                        tableName = ".".join(r[:3])

                        statement = 'ALTER TABLE {} DROP ROW FILTER;'.format(tableName)

                        args.logger.debug('statement:\n%s', statement)
                
                        results_df = sqlContext.sql(statement).toPandas()

                        args.logger.debug('response:\n%s', results_df.shape)

                    except Exception as e:
                        continue

                if results:
                    try:
                        statement = 'DROP FUNCTION {};'.format(row[0])

                        args.logger.debug('statement:\n%s', statement)
                
                        results_df = sqlContext.sql(statement).toPandas()

                        args.logger.debug('response:\n%s', results_df.shape)

                    except Exception as e:
                        pass

            except Exception as e:
                pass
    
    except Exception as e:
        print(e)
        pass




# get create or replace table rowlevel filters statements
def get_create_filters_commands(args=None, table_rowlevel_filters_df=None):
    schemaName = args.catalog + '.' + args.schema

    statement = ''

    statements = []

    lastFilter = None
    lastGroupName = None
    lastTableName = None
    
    for index, row in table_rowlevel_filters_df.sort_values(by=['filter', 'groupName', 'column']).iterrows():
        if row['filter'] != lastFilter: # if new filter
            if lastFilter is not None: # if not first filter
                statements.append('DROP FUNCTION {};'.format(lastFilter))

                statement = '{} ELSE TRUE END ELSE TRUE END;'.format(statement)

                statements.append(statement)

                statement = 'ALTER TABLE {} SET ROW FILTER {} ON ({})'.format(lastTableName, lastFilter, params.replace('STRING',''));

                statements.append(statement)

            # each new filter            
            params = ", ".join(table_rowlevel_filters_df[table_rowlevel_filters_df['filter']==row['filter']]['column'].drop_duplicates().apply(lambda x: x + ' STRING').tolist())

            statement = 'CREATE OR REPLACE FUNCTION {} ({}) RETURNS BOOLEAN RETURN CASE'.format(row['filter'], params)

            lastGroupName = None

            lastFilter = row['filter']

            lastTableName = row['catalog'] + '.' + row['schema'] + '.' + row['table']


        if row['groupName'] != lastGroupName: # if new filter group 
            if lastGroupName is not None: # if not the first filter group 
                statement = '{} ELSE TRUE END'.format(statement)          

            # each filter group
            statement = '{} WHEN IS_ACCOUNT_GROUP_MEMBER(\'{}\') THEN CASE'.format(statement, row['groupName'])

            lastGroupName = row['groupName']
 
        # each row filter
        statement = '{} WHEN {} == \'{}\' THEN FALSE'.format(statement, row['column'], row['codeValue'])


    if len(statement): # last statement
        statements.append('DROP FUNCTION {};'.format(lastFilter))

        statements.append('{} ELSE TRUE END ELSE TRUE END;'.format(statement))

        statements.append('ALTER TABLE {} SET ROW FILTER {} ON ({});'.format(lastTableName, lastFilter, params))


    return statements



# create or replace table rowlevel filters
def update_table_rowlevel_filters(args=None, table_rowlevel_filters_df=None):
    for statement in get_create_filters_commands(args, table_rowlevel_filters_df):
        try:
            args.logger.debug('statement:\n%s', statement)
            
            results_df = sqlContext.sql(statement).toPandas()
            
            args.logger.debug('response:\n%s', results_df.shape)
        
        except Exception as e:
            args.logger.debug('response:\nFAILED')
            pass



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
        '--db-catalog',
        dest='catalog',
        required=True,
        help='capability catalog name')

    parser.add_argument(
        '--db-schema',
        dest='schema',
        required=True,
        help='capability schema name')

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

    # session
    args.session = get_session(args=args)

    # get policies
    policies = get_policies(args=args)

    args.logger.info("got policies")        

    # get masking rules
    protection_rules_df = get_masking_rules(args=args, policies=policies)

    args.logger.info("got protection rules")        


    # use main catalog 
    schemaName = args.catalog + '.' + args.schema

    sqlContext.sql("use catalog {};".format(args.catalog))  

    # get masking functions
    masking_functions_df = get_masking_functions(args=args, protection_rules_df=protection_rules_df)

    args.logger.info("got masking functions")        

    # drop old masking functions
    drop_masking_functions(args=args, masking_functions_df=masking_functions_df)

    args.logger.info("dropped old masking functions")        

    # update newest masking functions
    update_masking_functions(args=args, masking_functions_df=masking_functions_df)

    args.logger.info("updated newest masking functions")        

    # store newest masking functions
    sdf = spark.createDataFrame(masking_functions_df[['tag', 'function']].sort_values(by=['tag']))
   
    sdf.write.mode("overwrite").saveAsTable("main.sbi_template_unitycatalog.tag_masking_functions")

    args.logger.info("saved newest masking functions")        

    # apply all masking functions
    apply_masking_functions(args=args, masking_functions_df=masking_functions_df)

    args.logger.info("set newest masking functions")        

    # drop duplicate assignments 
    sdf = sqlContext.sql("SELECT DISTINCT * FROM {}.tag_assignments".format(schemaName)) 

    sdf.write.mode("overwrite").saveAsTable("main.sbi_template_unitycatalog.tag_assignments")

    args.logger.info("drop duplicate assignments")        

    # get row level filters
    rowlevel_filters_df = get_rowlevel_filters(args=args, protection_rules_df=protection_rules_df)

    args.logger.info("got row level filters")        

    # get tables with row level filters
    table_rowlevel_filters_df = get_table_rowlevel_filters(args=args, rowlevel_filters_df=rowlevel_filters_df)

    table_rowlevel_filters_df = pd.merge(table_rowlevel_filters_df, rowlevel_filters_df,  how='left', left_on=table_rowlevel_filters_df['tag'].str.lower(), right_on = rowlevel_filters_df['dataClassification'].str.lower())
    
    args.logger.info("got table row level filters ")        

    # drop old table rowlevel filters
    drop_table_rowlevel_filters(args=args, table_rowlevel_filters_df=table_rowlevel_filters_df)

    args.logger.info("dropped old table row level filters ")        

    # update newest table rowlevel filters
    update_table_rowlevel_filters(args=args, table_rowlevel_filters_df=table_rowlevel_filters_df)

    args.logger.info("updated newest table rowlevel filters")        

    # store all table rowlevel filters
    table_rowlevel_filters_df.drop(columns=['key_0'], inplace=True)

    sdf=spark.createDataFrame(table_rowlevel_filters_df)
   
    sdf.write.mode("overwrite").saveAsTable("main.sbi_template_unitycatalog.row_access_filters")

    args.logger.info("saved row level filters")        

    args.logger.info("done")     
    
    return protection_rules_df, masking_functions_df, table_rowlevel_filters_df

