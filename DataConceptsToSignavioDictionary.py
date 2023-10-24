#!/usr/bin/env python
# coding: utf-8

# In[122]:


import sys
import requests
from requests.auth import HTTPBasicAuth
from ipywidgets import Layout
import ipywidgets as widgets


# In[123]:


def x(l, k, v): l[k] = v


# In[178]:


def w(w, o, d): v = w(options=sorted(o), description=d, layout=Layout(width='40%')); display(v); return v


# In[176]:


def getCustomAttributes(signavio):
    try:                  
        url = f"{signavio.get('host')}/p/meta"

        headers = {"x-signavio-id": signavio.get("authToken"), "accept":"application/json"}

        cookies = {"JSESSIONID": signavio.get("jsessionId"), "LBROUTEID": signavio.get("lbrouteId")}

        request = requests.get(url, headers=headers, cookies=cookies)

        return request.json()
    
    except Exception as e:
        return e


# In[126]:


def getDictionaryCategories(signavio):
    try:                  
        url = f"{signavio.get('host')}/p/glossarycategory?allCategories=true"

        headers = {"x-signavio-id": signavio.get("authToken"), "accept":"application/json"}

        cookies = {"JSESSIONID": signavio.get("jsessionId"), "LBROUTEID": signavio.get("lbrouteId")}

        request = requests.get(url, headers=headers, cookies=cookies)

        return request.json()
        
    except Exception as e:
        return e


# In[127]:


def addDictionaryEntry(signavio, dictionaryCategory, assetUuidCustomAttribute, assetTypeUuidCustomAttribute, asset):
    try:                  
        url = f"{signavio.get('host')}/p/glossary"

        headers = {"x-signavio-id": signavio.get("authToken"), "accept":"application/json", 'content-type': 'application/x-www-form-urlencoded'}

        cookies = {"JSESSIONID": signavio.get("jsessionId"), "LBROUTEID": signavio.get("lbrouteId")}

        metaDataValues= f"{{\"{assetUuidCustomAttribute.get('rep').get('id')}\":\"{asset.get('id')}\",\"{assetTypeUuidCustomAttribute.get('rep').get('id')}\":\"{asset.get('type').get('id')}\"}}"

        payload = f"title={asset.get('name')}&category={dictionaryCategory.get('href').split('/')[-1]}&description={asset.get('description') if 'description' in asset else ''}&metaDataValues={metaDataValues}"

        request = requests.post(url, headers=headers, cookies=cookies, data=payload)

        return request.json()
        
    except Exception as e:
        return e    


# In[128]:


def getDictionaryEntry(signavio, dictionaryCategory, asset):
    try:                  
        url = f"{signavio.get('host')}/p/glossary?q={asset.get('name')}&category={dictionaryCategory.get('href').split('/')[-1]}"

        headers = {"x-signavio-id": signavio.get("authToken"), "accept":"application/json", 'content-type': 'application/x-www-form-urlencoded'}

        cookies = {"JSESSIONID": signavio.get("jsessionId"), "LBROUTEID": signavio.get("lbrouteId")}

        request = requests.get(url, headers=headers, cookies=cookies)

        return request.json()
        
    except Exception as e:
        return e    


# In[129]:


def getAssetsOfTypeAndStatus(collibra, community, asset_types=None, status_types=None):
    try:
        asset_types_query = "".join([f"&typeIds={t.get('id')}" for t in asset_types]) if asset_types is not None else ""

        status_types_query = "".join([f"&statusIds={t.get('id')}" for t in status_types]) if status_types is not None else ""

        response = collibra.get("session").get(f"{collibra.get('endpoint')}/assets?communityId={community.get('id')}{asset_types_query}{status_types_query}")

        return response.json()
    
    except Exception as e:
        return e


# In[130]:


signavio = {"host": "https://editor.signavio.com", "tenant": "93ab506a8d87439f9fbb680fdbc95d4b", "username": "antonio.castelo@collibra.com", "password": "W2.Collibra"}


# In[131]:


try:
    url = f"{signavio.get('host')}/p/login"

    data = {"name": signavio.get("username"), "password": signavio.get("password"), "tenant": signavio.get("tenant"), "tokenonly": "true"}

    request = requests.post(url, data)

    authToken = request.content.decode("utf-8")

    jsessionId = request.cookies.get("JSESSIONID")
    
    lbrouteId = request.cookies.get("LBROUTEID")

    signavio = {"host": signavio.get("host"), "tenant": signavio.get("tenant"), "authToken": authToken, "jsessionId": jsessionId, "lbrouteId": lbrouteId}

except Exception as e:
    print(e)
    sys.exit(1)


# In[132]:


collibra = {"endpoint": "https://print.collibra.com/rest/2.0", "username": "DataLakeAdmin", "password": "W2.Collibra"}


# In[133]:


try:
    collibra["session"] = requests.Session()
    
    collibra.get("session").auth = HTTPBasicAuth(collibra.get("username"), collibra.get("password"))

except Exception as e:
    print(e)
    sys.exit(1)


# In[134]:


asset_types = {}

try:
    response = collibra.get("session").get(f"{collibra.get('endpoint')}/assetTypes")

    [x(asset_types, r.get("name"), r) for r in response.json()["results"]]

except Exception as e:
    print(e)
    sys.exit(1)


# In[135]:


attribute_types = {}

try:
    response = collibra.get("session").get(f"{collibra.get('endpoint')}/attributeTypes")
    
    [x(attribute_types, r.get("name"), r) for r in response.json()["results"]]
        
except Exception as e:
    print(e)
    sys.exit(1)


# In[136]:


status_types = {}

try:
    response = collibra.get("session").get(f"{collibra.get('endpoint')}/statuses")

    [x(status_types, r.get("name"), r) for r in response.json()["results"]]

except Exception as e:
    print(e)
    sys.exit(1)


# In[137]:


communities = {}

try:
    response = collibra.get("session").get(f"{collibra.get('endpoint')}/communities")

    [x(communities, r.get("name"), r) for r in response.json()["results"]]

except Exception as e:
    print(e)
    sys.exit(1)


# In[179]:


widget = w(widgets.SelectMultiple, [f"{k}" for k,v in communities.items()], 'Communities')


# In[139]:


chosenCommunities = [communities.get(c) for c in widget.value]


# In[180]:


widget = w(widgets.SelectMultiple, [f"{k}" for k,v in asset_types.items()], 'Asset Types')


# In[141]:


chosenAssetTypes = [asset_types.get(t) for t in widget.value]


# In[181]:


widget = w(widgets.SelectMultiple, [f"{k}" for k,v in status_types.items()], 'Status Types')


# In[143]:


chosenStatusTypes = [status_types.get(t) for t in widget.value]


# In[151]:


dataConcepts = None

try:
    dataConcepts = [getAssetsOfTypeAndStatus(collibra, c, chosenAssetTypes, chosenStatusTypes) for c in chosenCommunities]
    
except Exception as e:
    print(e)
    sys.exit(1)


# In[153]:


dictionaryCategories = {}

try:
    [x(dictionaryCategories, c.get("rep").get("name"), c) for c in getDictionaryCategories(signavio) if c.get("rel") == "cat"]

except Exception as e:
    print(e)
    sys.exit(1)


# In[182]:


widget = w(widgets.Dropdown, [f"{k}" for k,v in dictionaryCategories.items()], 'Category')


# In[155]:


chosenDictionaryCategory = dictionaryCategories.get(widget.value)


# In[156]:


bindingCategory = chosenDictionaryCategory.get("href").split("/")[-1]


# In[157]:


def isCustomAttributeValid(customAttribute, bindingCategory):
    try:
        return len([b for b in customAttribute.get("rep").get("glossaryBindings") if b.get("category") is not None and b.get("category") == bindingCategory])>0

    except Exception as e:
        return False
    
customAttributes = {}

try:
    [x(customAttributes, a.get("rep").get("name"), a) for a in getCustomAttributes(signavio) if isCustomAttributeValid(a, bindingCategory)]
    
except Exception as e:
    print(e)
    sys.exit(1)


# In[183]:


widget = w(widgets.Dropdown, [f"{k}" for k,v in customAttributes.items()], 'Asset Uuid')


# In[159]:


chosenAssetUuidCustomAttribute = customAttributes.get(widget.value)


# In[184]:


widget = w(widgets.Dropdown, [f"{k}" for k,v in customAttributes.items()], 'Type Uuid')


# In[161]:


chosenAssetTypeUuidCustomAttribute = customAttributes.get(widget.value)


# In[162]:


dictionaryEntriesResults = [addDictionaryEntry(signavio, chosenDictionaryCategory, chosenAssetUuidCustomAttribute, chosenAssetTypeUuidCustomAttribute, a) for a in dataConcepts[0].get("results")]


# In[35]:


dictionaryEntriesFailed = [r for r in dictionaryEntriesResults if 'errors' in r]


# In[36]:


dictionaryEntriesFound = [getDictionaryEntry(signavio, chosenDictionaryCategory, a) for a in dataConcepts[0].get("results")]


# In[ ]:


#update collibra asset with the signavio href...

