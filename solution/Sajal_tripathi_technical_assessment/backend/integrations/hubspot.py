import json
import secrets
import base64
from typing import List
from urllib.parse import urlencode

import requests
import httpx
import asyncio
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

CLIENT_ID = 'xxx'
CLIENT_SECRET = 'xxx'


REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
SCOPE = 'crm.objects.appointments.read crm.objects.appointments.write crm.objects.carts.read crm.objects.carts.write crm.objects.companies.read crm.objects.companies.write crm.objects.contacts.read crm.objects.contacts.write'
async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id,
    }
    saved_state_json = json.dumps(state_data)
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', saved_state_json, expire=600)

    encoded_state = base64.urlsafe_b64encode(saved_state_json.encode('utf-8')).decode('utf-8')

    query = urlencode({
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'response_type': 'code',
        'state': encoded_state,
    })
    auth_url = f'https://app.hubspot.com/oauth/authorize?{query}'
    return auth_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error'))

    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    
    try:
        padded = encoded_state + '=' * (-len(encoded_state) % 4)
        state_data = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid state parameter.')

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    token_url = 'https://api.hubapi.com/oauth/v1/token'

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                token_url,
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )

    if response.status_code >= 400:
        raise HTTPException(status_code=400, detail='Failed to exchange code for tokens')

    await add_key_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600
    )

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    return credentials

def _to_integration_item_from_hs_object(obj: dict, object_type: str) -> IntegrationItem:
    properties = obj.get('properties', {})
    if object_type == 'contact':
        first_name = properties.get('firstname', '')
        last_name = properties.get('lastname', '')
        display_name = (first_name + ' ' + last_name).strip() or properties.get('email', 'contact')
        name = f'Contact {display_name}'
    elif object_type == 'deal':
        deal_name = properties.get('dealname', 'Unnamed Deal')
        name = f'Deal {deal_name}'
    else:
        name = f'{object_type.title()} {obj.get("id", "")}'

    return IntegrationItem(
        id=obj.get('id'),
        type=object_type,
        name=name,
        creation_time=properties.get('createdate') or obj.get('createdAt'),
        last_modified_time=properties.get('hs_lastmodifieddate') or obj.get('updatedAt'),
        parent_id=None,
    )

def _fetch_hubspot_objects(access_token: str, object_type: str, limit: int = 50) -> List[dict]:
    url = f'https://api.hubapi.com/crm/v3/objects/{object_type}s'
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {'limit': limit}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        return []
    return response.json().get('results', [])

async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    creds = json.loads(credentials)
    access_token = creds.get('access_token')
    if not access_token:
        return []

    contacts = _fetch_hubspot_objects(access_token, 'contact', limit=50)
    deals = _fetch_hubspot_objects(access_token, 'deal', limit=50)

    items: List[IntegrationItem] = []
    for c in contacts:
        items.append(_to_integration_item_from_hs_object(c, 'contact'))
    for d in deals:
        items.append(_to_integration_item_from_hs_object(d, 'deal'))

    print(f'list_of_integration_item_metadata: {items}')
    return items