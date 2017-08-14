# The MIT License
#
#  Copyright 2016-2017 UB Dortmund <daten.ub@tu-dortmund.de>.
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.

import datetime
import logging
from logging.handlers import RotatingFileHandler
import simplejson as json
import redis
import requests
from requests import RequestException
from urllib import parse

import os
import sys
sys.path.append('%s/orcid_sync/crossref2mms' % os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crossref2mms import crossref2mms
from datacite2mms import datacite2mms
from orcid_mms import orcid_mms

try:
    import local_secrets as secrets
except ImportError:
    import secrets

log_formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")

logger = logging.getLogger("ORCID")
logger.setLevel(logging.DEBUG)

handler = RotatingFileHandler(secrets.LOGFILE, maxBytes=1000000, backupCount=1)
handler.setFormatter(log_formatter)

logger.addHandler(handler)


# see also: https://github.com/ORCID/ORCID-Source/blob/master/orcid-model/src/main/resources/record_2.0/README.md
# --- request helper ---- #
def _orcid_api_get_request(affiliation='', orcid_id='', access_token='', section='', put_code=None):

    sandbox = '.sandbox'
    if affiliation and not secrets.ORCID_API_DATA.get(affiliation).get('sandbox'):
        sandbox = ''

    endpoint = 'https://api%s.orcid.org/v2.0/%s/%s' % (sandbox, orcid_id, section)
    if put_code:
        endpoint += '/%s' % put_code

    return requests.get(endpoint, headers={'Accept': 'application/json', 'Authorization': 'Bearer %s' % access_token}).json()


def _orcid_api_post_request(affiliation='', orcid_id='', access_token='', section='', put_code=None, data=''):

    sandbox = '.sandbox'
    if affiliation and not secrets.ORCID_API_DATA.get(affiliation).get('sandbox'):
        sandbox = ''

    endpoint = 'https://api%s.orcid.org/v2.0/%s/%s' % (sandbox, orcid_id, section)
    if put_code:
        endpoint += '/%s' % put_code

    if data:
        response = requests.post(endpoint, headers={'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}, data=data)

        if response.status_code == 200 or response.status_code == 201:

            logger.info(response.status_code)
            logger.info(response.headers)
            logger.info(response.content.decode("utf-8"))
            return response.headers.get('Location').split('%s/' % section)[1]
        else:
            logger.error(response.status_code)
            logger.error(response.text)
            logger.error(response.content.decode("utf-8"))
            logger.error(json.dumps(json.loads(data), indent=2))
            return None
    else:
        logger.error('no data to post: ' % data)
        return None


def _orcid_api_put_request(affiliation='', orcid_id='', access_token='', section='', put_code=None, data=''):

    sandbox = '.sandbox'
    if affiliation and not secrets.ORCID_API_DATA.get(affiliation).get('sandbox'):
        sandbox = ''

    endpoint = 'https://api%s.orcid.org/v2.0/%s/%s' % (sandbox, orcid_id, section)
    if put_code:
        endpoint += '/%s' % put_code

    if data:
        response = requests.put(endpoint, headers={'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}, data=data)

        if response.status_code != 200:

            logger.error(response.status_code)
            logger.error(response.content.decode("utf-8"))
            logger.error(json.dumps(json.loads(data), indent=2))
    else:
        logger.error('no data to put: ' % data)


# ---- ORCID functions ---- #
def orcid_login_url(affiliation=None, email=None, scopes=None):
    # see also: https://members.orcid.org/api/tutorial/get-orcid-id
    if affiliation:

        sandbox = 'sandbox.'
        if not secrets.ORCID_API_DATA.get(affiliation).get('sandbox'):
            sandbox = ''

        if not isinstance(scopes, str):
            scopes = " ".join(sorted(set(scopes)))

        data = [("client_id", secrets.ORCID_API_DATA.get(affiliation).get('client_id')), ("scope", scopes),
                ("response_type", "code"),
                ("redirect_uri", secrets.ORCID_API_DATA.get(affiliation).get('redirect_uri'))]

        if email:
            data.append(("email", email))

        return 'https://%sorcid.org/oauth/authorize?%s' % (sandbox, parse.urlencode(data))
    else:
        return ''


def orcid_get_token(affiliation='', code=''):
    # see also: https://members.orcid.org/api/tutorial/get-orcid-id
    if affiliation:
        sandbox = 'sandbox.'
        if not secrets.ORCID_API_DATA.get(affiliation).get('sandbox'):
            sandbox = ''

        data = {
            'client_id': secrets.ORCID_API_DATA.get(affiliation).get('client_id'),
            'client_secret': secrets.ORCID_API_DATA.get(affiliation).get('client_secret'),
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': secrets.ORCID_API_DATA.get(affiliation).get('redirect_uri')
        }

        endpoint = 'https://%sorcid.org/oauth/token' % sandbox

        return requests.post(endpoint, headers={'Accept': 'application/json'}, data=data).json()

    else:
        return ''


# ---- ORCID functions ---- #
def orcid_user_info(affiliation='', orcid_id='', access_token=''):

    try:
        # get public_info from orcid
        public_info = _orcid_api_get_request(affiliation=affiliation, orcid_id=orcid_id, section='person', access_token=access_token)

        return public_info

    except RequestException as e:
        logger.error('ORCID-ERROR: %s' % e.response.text)


def orcid_add_records(affiliation='', orcid_id='', access_token='', works=None):
    if works is None:
        works = {}

    if works:

        for record_id in works.keys():
            # logger.info('work: %s' % work)

            work = works.get(record_id)[0]
            # print(work)

            try:
                put_code = _orcid_api_post_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='work', data=json.dumps(work))

                if put_code:
                    orcid_record = _orcid_api_get_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='work', put_code=put_code)
                    update_json = {}
                    orcid_sync = {
                        'orcid_id': orcid_id,
                        'orcid_put_code': str(put_code),
                        'orcid_visibility': orcid_record.get('visibility')
                    }
                    update_json['orcid_sync'] = [orcid_sync]

                    logger.info('PUT /work/%s' % record_id)
                    # PUT request
                    logger.info(update_json)
                    try:
                        # put data
                        response = requests.put(
                            '%s/%s/%s' % (secrets.MMS_API, 'work', record_id),
                            headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer %s' % secrets.MMS_API_TOKEN
                            },
                            data=json.dumps(update_json)
                            )
                        status = response.status_code
                        logger.info('STATUS: %s' % status)
                        if status == 200:
                            response_json = json.loads(response.content.decode("utf-8"))
                            # logger.info(response_json.get('work'))
                            if response_json.get('message'):
                                logger.info(response_json.get('message'))
                        else:
                            logger.error('ERROR: %s: %s' % (status, response.content.decode("utf-8")))

                    except requests.exceptions.ConnectionError as e:
                        logger.error(e)
            except RequestException as e:
                logger.error('ORCID-ERROR: %s' % e.response.text)


def orcid_update_records(affiliation='', orcid_id='', access_token='', works=None):
    if works is None:
        works = {}

    if works:

        for record_id in works.keys():
            # logger.info('work: %s' % work)

            work = works.get(record_id).get('orcid_record')[0]
            # print(json.dumps(work, indent=4))

            try:
                logger.debug('record_id: %s' % record_id)
                logger.debug('id type: %s' % type(record_id))
                logger.debug('work_id: %s' % works.get(record_id).get('record_id'))
                put_code = int(record_id)
                _orcid_api_put_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='work', put_code=put_code, data=json.dumps(work))

                orcid_record = _orcid_api_get_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='work', put_code=put_code)
                update_json = {}
                orcid_sync = {
                    'orcid_id': orcid_id,
                    'orcid_put_code': str(put_code),
                    'orcid_visibility': orcid_record.get('visibility')
                }
                update_json['orcid_sync'] = [orcid_sync]

                logger.info('PUT /work/%s' % record_id)
                # PUT request
                logger.info(update_json)
                try:
                    # put data
                    response = requests.put(
                        '%s/%s/%s' % (secrets.MMS_API, 'work', record_id),
                        headers={'Content-Type': 'application/json',
                                 'Authorization': 'Bearer %s' % secrets.MMS_API_TOKEN},
                        data=json.dumps(update_json)
                    )
                    status = response.status_code
                    logger.info('STATUS: %s' % status)
                    if status == 200:
                        response_json = json.loads(response.content.decode("utf-8"))
                        # logger.info(response_json.get('work'))
                        if response_json.get('message'):
                            logger.info(response_json.get('message'))
                    else:
                        logger.error('ERROR: %s: %s' % (status, response.content.decode("utf-8")))

                except requests.exceptions.ConnectionError as e:
                    logger.error(e)

            except RequestException as e:
                logger.error('ORCID-ERROR: %s' % e.response.text)


def orcid_add_external_id(affiliation='', orcid_id='', access_token='', external_id=None):

    put_code = ''

    try:

        logger.info('external_id: %s' % external_id)

        put_code = _orcid_api_post_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='external-identifiers', data=external_id)

        # get info from orcid again
        info = _orcid_api_get_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='external-identifiers', put_code=put_code)
        logger.info('info: %s' % info)

    except RequestException as e:
        logger.error('ORCID-ERROR: %s' % e.response.text)

    return put_code


def orcid_read_works(affiliation='', orcid_id='', access_token=''):

    works = []

    try:

        works = _orcid_api_get_request(affiliation=affiliation, orcid_id=orcid_id, access_token=access_token, section='works')
        works = works.get('group')

    except RequestException as e:
        logger.error('ORCID-ERROR: %s' % e.response.text)

    return works


# ---- MMS functions ---- #

def get_new_records(affiliation='', orcid_id=''):

    query_string = 'q=orcid:%s AND -orcid_put_code:[\'\' TO *]' % orcid_id
    rows = 100000

    orcid_records = {}
    try:
        response = requests.get('%s/%s?%s&rows=%s' % (secrets.MMS_API, 'works/search', query_string, rows),
                                headers={'Accept': 'application/json'},
                                )
        status = response.status_code
        if status == 200:
            records = json.loads(response.content.decode('utf8'))

            if records:
                for record in records:
                    orcid_records.setdefault(record.get('id'),
                                             orcid_mms.mms2orcid(affiliation=affiliation, mms_records=[record]))
            else:
                logger.info('No records found for orcid_id: %s' % orcid_id)
        else:
            logger.info('No records found for orcid_id: %s' % orcid_id)
            logger.info('message: %s - %s' % (status, response.content.decode('utf8')))

    except requests.exceptions.ConnectionError as e:
        logger.error(e)

    return orcid_records


def get_updated_records(affiliation='', orcid_id=''):

    query_string = 'q=orcid:%s AND orcid_put_code:[\'\' TO *]' % orcid_id
    rows = 100000

    orcid_records = {}
    try:
        response = requests.get('%s/%s?%s&rows=%s' % (secrets.MMS_API, 'works/search', query_string, rows),
                                headers={'Accept': 'application/json'},
                                )
        status = response.status_code
        if status == 200:
            records = json.loads(response.content.decode('utf8'))

            if records:
                for record in records:
                    # search for the matching put_code
                    put_code = None
                    for orcid_data in record.get('orcid_sync'):
                        if orcid_id == orcid_data.get('orcid_id'):
                            put_code = orcid_data.get('orcid_put_code')
                            break

                    if put_code:
                        put_record = orcid_mms.mms2orcid(affiliation=affiliation, mms_records=[record])
                        put_record[0]['put-code'] = put_code
                        orcid_records.setdefault(put_code, {'record_id': record.get('id'), 'orcid_record': put_record})
                    else:
                        logger.error('data error in mms! orcid_data in index but not in record itself. (record %s)' % record.get('id'))
            else:
                logger.info('No records found for orcid_id: %s' % orcid_id)
        else:
            logger.info('No records found for orcid_id: %s' % orcid_id)

    except requests.exceptions.ConnectionError as e:
        logger.error(e)

    return orcid_records


# ---- utils ---- #


def dict_compare(d1, d2):
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o: (d1[o], d2[o]) for o in intersect_keys if d1[o] != d2[o]}
    same = set(o for o in intersect_keys if d1[o] == d2[o])
    return added, removed, modified, same


# ---- ORCID plattform to MMS ---- #
def sync_orcid_to_mms(orcid_id=''):
    try:
        response = requests.get('%s/%s/%s' % (secrets.MMS_API, 'user', orcid_id),
                                headers={'Accept': 'application/json', 'Authorization': 'Bearer %s' % secrets.MMS_API_TOKEN},
                                )
        status = response.status_code
        if status == 200:
            user = json.loads(response.content.decode('utf8'))
            if user:
                if '/read-limited' in user.get('orcidscopes'):
                    works = orcid_read_works(affiliation=user.get('affiliation'), orcid_id=orcid_id,
                                             access_token=user.get('orcidaccesstoken'))
                    logger.info('results from ORCID: %s\n' % len(works))
                    if works:
                        cnt = 1
                        for work in works:
                            logger.info('%s/%s' % (cnt, len(works)))
                            cnt += 1
                            do_break = False
                            hb2_record_id = None
                            orcid_record = None
                            orcid_sync = None

                            for work_sum in work.get('work-summary'):
                                # - putcode is not in hb2
                                try:
                                    response = requests.get('%s/%s/%s' % (secrets.MMS_API, 'work',
                                                                          work_sum.get('put-code')),
                                                            headers={'Accept': 'application/json'},
                                                            )
                                    status = response.status_code
                                    if status == 200:
                                        hb2_record_id = json.loads(response.content.decode('utf8')).get('id')
                                        do_break = True
                                        orcid_sync = {
                                            'orcid_id': orcid_id,
                                            'orcid_put_code': str(work_sum.get('put-code')),
                                            'orcid_visibility': str(work_sum.get('visibility'))
                                        }
                                        break
                                    else:
                                        orcid_sync = {
                                            'orcid_id': orcid_id,
                                            'orcid_put_code': '',
                                            'orcid_visibility': str(work_sum.get('visibility'))
                                        }

                                        for ext_id in work_sum.get('external-ids').get('external-id'):
                                            # if exists record with doi
                                            if ext_id.get('external-id-type') == 'doi':
                                                doi = ext_id.get('external-id-value')\
                                                    .replace('http://dx.doi.org/', '').replace('doi:', '')

                                                try:
                                                    work_id = parse.quote_plus(parse.quote_plus(doi))
                                                    response = requests.get(
                                                        '%s/%s/%s' % (secrets.MMS_API, 'work', work_id),
                                                        headers={'Accept': 'application/json'},
                                                        )
                                                    status = response.status_code
                                                    if status == 200:
                                                        hb2_record_id = json.loads(response.content).get('id')
                                                        orcid_record = work_sum
                                                        do_break = True
                                                        break
                                                    else:
                                                        logger.info('\t\tNo record found for "%s"' % work_id)

                                                except requests.exceptions.ConnectionError:
                                                    logger.error('REQUEST ERROR: %s' % ext_id.get('external-id-value'))

                                            # if exists record with pmid
                                            if ext_id.get('external-id-type') == 'pmid':
                                                pmid = ext_id.get('external-id-value')
                                                # print('\tpmid?: %s' % pmid)

                                                try:
                                                    response = requests.get(
                                                        '%s/%s/%s' % (secrets.MMS_API, 'work', pmid),
                                                        headers={'Accept': 'application/json'},
                                                        )
                                                    status = response.status_code
                                                    if status == 200:
                                                        hb2_record_id = json.loads(response.content.decode('utf8')).get('id')
                                                        orcid_record = work_sum
                                                        do_break = True
                                                        break
                                                    else:
                                                        logger.info('\t\tNo record found for "%s"' % pmid)

                                                except requests.exceptions.ConnectionError:
                                                    logger.error('REQUEST ERROR: %s' % ext_id.get('external-id-value'))

                                            # if exists record with wos_id / isi_id
                                            if ext_id.get('external-id-type') == 'wosuid':
                                                wosuid = ext_id.get('external-id-value').replace('WOS:', '')
                                                # print('\twosuid?: %s' % wosuid)

                                                try:
                                                    response = requests.get(
                                                        '%s/%s/%s' % (secrets.MMS_API, 'work', wosuid),
                                                        headers={'Accept': 'application/json'},
                                                        )
                                                    status = response.status_code
                                                    if status == 200:
                                                        hb2_record_id = json.loads(response.content.decode('utf8')).get('id')
                                                        orcid_record = work_sum
                                                        do_break = True
                                                        break
                                                    else:
                                                        logger.info('\t\tNo record found for "%s"' % wosuid)

                                                except requests.exceptions.ConnectionError:
                                                    logger.error('REQUEST ERROR: %s' % ext_id.get('external-id-value'))

                                            # if exists record with scopus_id / e_id
                                            if ext_id.get('external-id-type') == 'eid':
                                                eid = ext_id.get('external-id-value')
                                                # print('\teid?: %s' % eid)

                                                try:
                                                    response = requests.get(
                                                        '%s/%s/%s' % (secrets.MMS_API, 'work', eid),
                                                        headers={'Accept': 'application/json'},
                                                        )
                                                    status = response.status_code
                                                    if status == 200:
                                                        hb2_record_id = json.loads(response.content.decode('utf8')).get('id')
                                                        orcid_record = work_sum
                                                        do_break = True
                                                        break
                                                    else:
                                                        logger.info('\t\tNo record found for "%s"' % eid)

                                                except requests.exceptions.ConnectionError:
                                                    logger.error('REQUEST ERROR: %s' % ext_id.get('external-id-value'))

                                            # - isbn of book is not in hb2
                                            if work_sum.get('type') == 'BOOK' and ext_id.get('external-id-type') == 'isbn':
                                                # print('isbn: %s' % ext_id.get('external-id-value'))
                                                records = get_new_records(affiliation=user.get('affiliation'),
                                                                          query='isbn:%s' % ext_id.get('external-id-value'))
                                                if len(records) == 1:
                                                    hb2_record_id = list(records.keys())[0]
                                                    orcid_record = records.get(hb2_record_id)
                                                    do_break = True
                                                    break
                                                else:
                                                    logger.info('\t\tMore than one record found for "%s"' % ext_id.get('external-id-value'))

                                except requests.exceptions.ConnectionError:
                                    logger.error('REQUEST ERROR: %s' % work_sum.get('put-code'))

                                if do_break:
                                    break
                                else:
                                    orcid_record = work_sum

                            if do_break:
                                # print('\t\t>> record already exists: %s <<' % hb2_record_id)
                                logger.info('>> UPDATE RECORD <<')
                                if orcid_record:
                                    # add orcid_put_code, wos_id, scopus_id and pmid to hb 2 record
                                    update_json = {}
                                    # print('\tadd orcid_put_code "%s"' % work_sum.get('put-code'))
                                    if orcid_sync:
                                        update_json['orcid_sync'] = [orcid_sync]

                                    for extid in work_sum.get('external-ids').get('external-id'):
                                        if extid.get('external-id-type') == 'eid':
                                            # print('\tadd scopus_id "%s"' % extid.get('external-id-value'))
                                            update_json['scopus_id'] = extid.get('external-id-value')
                                        if extid.get('external-id-type') == 'wosuid':
                                            # print('\tadd wosuid "%s"' % extid.get('external-id-value'))
                                            update_json['WOSID'] = extid.get('external-id-value').replace('WOS:', '')
                                        if extid.get('external-id-type') == 'pmid':
                                            # print('\tadd pmid "%s"' % extid.get('external-id-value'))
                                            update_json['PMID'] = extid.get('external-id-value')
                                    if update_json:
                                        logger.info('PUT /work/%s (do_break)' % hb2_record_id)
                                        # PUT request
                                        # logger.info('%s: %s' % (hb2_record_id, json.dumps(update_json, indent=4)))
                                        try:
                                            # put data
                                            response = requests.put(
                                                '%s/%s/%s' % (secrets.MMS_API, 'work', hb2_record_id),
                                                headers={
                                                    'Content-Type': 'application/json',
                                                    'Authorization': 'Bearer %s' % secrets.MMS_API_TOKEN},
                                                data=json.dumps(update_json)
                                                )
                                            status = response.status_code
                                            logger.info('STATUS: %s' % status)
                                            if status == 200:
                                                response_json = json.loads(response.content.decode("utf-8"))
                                                # logger.info(response_json.get('work'))
                                                if response_json.get('message'):
                                                    logger.info(response_json.get('message'))
                                            else:
                                                logger.error('ERROR: %s: %s' % (status, response.content.decode("utf-8")))
                                        except requests.exceptions.ConnectionError as e:
                                            logger.error(e)
                                else:
                                    logger.error("This isn't possible! (break=record available without data)")
                            else:
                                logger.info('>> ADD RECORD <<')
                                thedata = None
                                doi = None
                                if orcid_record:
                                    # if exists doi: get record from crossref or datacite
                                    for extid in orcid_record.get('external-ids').get('external-id'):
                                        if extid.get('external-id-type') == 'doi':
                                            doi = extid.get('external-id-value')
                                            break

                                    # print(doi)
                                    if doi:
                                        if 'doi.org/' in doi:
                                            # print(doi.split('doi.org/')[1])
                                            doi = doi.split('doi.org/')[1]

                                        thedata = crossref2mms.crossref2mms(doi=doi)
                                        # if thedata == []: datacite request
                                        if not thedata:
                                            thedata = datacite2mms.datacite2mms(doi=doi)

                                        # print(json.dumps(thedata, indent=4))

                                        if thedata:
                                            # edit author information about the orcid member using all "aka"s
                                            public_info = orcid_user_info(affiliation=user.get('affiliation'),
                                                                          orcid_id=orcid_id,
                                                                          access_token=user.get('orcidaccesstoken'))
                                            # print(json.dumps(public_info, indent=4))
                                            idx_to_change = -1
                                            names = list(public_info.get('other-names').get('other-name'))
                                            names.append('%s, %s' % (public_info.get('name').get('family-name').get('value'), public_info.get('name').get('given-names').get('value')))
                                            names.append('%s, %s.' % (public_info.get('name').get('family-name').get('value'), str(public_info.get('name').get('given-names').get('value'))[0]))
                                            names.append('%s %s' % (public_info.get('name').get('given-names').get('value'), public_info.get('name').get('family-name').get('value')))
                                            # print(names)
                                            # print(thedata.get('person'))
                                            for other_name in names:
                                                break_it = False
                                                if thedata.get('person'):
                                                    for idx, person in enumerate(thedata.get('person')):
                                                        name = '%s %s' % (person.get('name').split(', ')[1],
                                                                          person.get('name').split(', ')[0])
                                                        # print('%s vs. %s' % (name, other_name))
                                                        if (type(other_name) is str and name.strip() == other_name.strip()) \
                                                                or (type(other_name) is dict and name == other_name.get('content')):
                                                            idx_to_change = idx
                                                            break_it = True
                                                            break
                                                if break_it:
                                                    break
                                            # print(idx_to_change)

                                            if idx_to_change > -1:
                                                person = {
                                                    'name': thedata['person'][idx_to_change].get('name'),
                                                    'orcid': orcid_id,
                                                    'role': ['aut']
                                                }

                                                try:
                                                    response = requests.get(
                                                        '%s/%s/%s' % (secrets.MMS_API, 'person', orcid_id),
                                                        headers={'Accept': 'application/json'},
                                                        )
                                                    status = response.status_code
                                                    if status == 200:
                                                        person_data = json.loads(response.content.decode('utf8'))
                                                        if person_data.get('gnd'):
                                                            person['gnd'] = person_data.get('gnd')
                                                    else:
                                                        logger.info('\t\tNo record found for "%s"' % orcid_id)

                                                except requests.exceptions.ConnectionError:
                                                    logger.error('REQUEST ERROR: %s' % orcid_id)

                                                if user.get('affiliation') == 'tudo':
                                                    person['tudo'] = True
                                                    person['rubi'] = False
                                                elif user.get('affiliation') == 'rub':
                                                    person['tudo'] = False
                                                    person['rubi'] = True
                                                else:
                                                    person['tudo'] = False
                                                    person['rubi'] = False

                                                thedata['person'][idx_to_change] = person

                                            if user.get('affiliation') == 'tudo':
                                                thedata['catalog'] = ['tudo']
                                            elif user.get('affiliation') == 'rub':
                                                thedata['catalog'] = ['rub']
                                            else:
                                                thedata['catalog'] = ['tmp']

                                            for extid in orcid_record.get('external-ids').get('external-id'):
                                                if extid.get('external-id-type') == 'eid':
                                                    # print('\tadd scopus_id "%s"' % extid.get('external-id-value'))
                                                    thedata['scopus_id'] = extid.get('external-id-value')
                                                if extid.get('external-id-type') == 'wosuid':
                                                    # print('\tadd wosuid "%s"' % extid.get('external-id-value'))
                                                    thedata['WOSID'] = extid.get('external-id-value')
                                                if extid.get('external-id-type') == 'pmid':
                                                    # print('\tadd pmid "%s"' % extid.get('external-id-value'))
                                                    thedata['PMID'] = extid.get('external-id-value')

                                            thedata['note'] = 'added by ORCID synchronization'
                                            thedata['owner'] = ['daten.ub@tu-dortmund.de']
                                            # print(json.dumps(thedata, indent=4))
                                        else:
                                            # logger.info(json.dumps(orcid_record, indent=4))
                                            thedata = orcid_mms.orcid2mms(orcid_id, orcid_record)
                                            if thedata:
                                                # add author via orcid_user_info
                                                public_info = orcid_user_info(
                                                    affiliation=user.get('affiliation'),
                                                    orcid_id=orcid_id,
                                                    access_token=user.get('orcidaccesstoken'))
                                                person = {
                                                    'name': '%s, %s' % (public_info.get('name').get('family-name').get('value'),
                                                                        public_info.get('name').get('given-names').get(
                                                                            'value')),
                                                    'orcid': orcid_id,
                                                    'role': ['aut']
                                                }
                                                if user.get('affiliation') == 'tudo':
                                                    person['tudo'] = True
                                                    person['rubi'] = False
                                                    thedata['catalog'] = ['tudo']
                                                elif user.get('affiliation') == 'rub':
                                                    person['tudo'] = False
                                                    person['rubi'] = True
                                                    thedata['catalog'] = ['rub']
                                                else:
                                                    person['tudo'] = False
                                                    person['rubi'] = False
                                                    thedata['catalog'] = ['tmp']

                                                thedata['person'] = [person]

                                    else:
                                        # logger.info(json.dumps(orcid_record, indent=4))
                                        thedata = orcid_mms.orcid2mms(orcid_id, orcid_record)
                                        if thedata:
                                            # add author via orcid_user_info
                                            public_info = orcid_user_info(affiliation=user.get('affiliation'),
                                                                          orcid_id=orcid_id,
                                                                          access_token=user.get('orcidaccesstoken'))
                                            person = {
                                                'name': '%s, %s' % (public_info.get('name').get('family-name').get('value'),
                                                                    public_info.get('name').get('given-names').get('value')),
                                                'orcid': orcid_id,
                                                'role': ['aut']
                                            }
                                            if user.get('affiliation') == 'tudo':
                                                person['tudo'] = True
                                                person['rubi'] = False
                                                thedata['catalog'] = ['tudo']
                                            elif user.get('affiliation') == 'rub':
                                                person['tudo'] = False
                                                person['rubi'] = True
                                                thedata['catalog'] = ['rub']
                                            else:
                                                person['tudo'] = False
                                                person['rubi'] = False
                                                thedata['catalog'] = ['tmp']

                                            thedata['person'] = [person]

                                if thedata:

                                    # add orcid_put_code to source_list
                                    sources = redis.StrictRedis(host=secrets.REDIS_SOURCE_IDS_HOST,
                                                                port=secrets.REDIS_SOURCE_IDS_PORT,
                                                                db=secrets.REDIS_SOURCE_IDS_DB)

                                    if not sources.exists('orcid:%s' % work_sum.get('put-code')):
                                        logger.info('POST /work')
                                        # POST request
                                        # logger.info(json.dumps(thedata, indent=4))
                                        try:
                                            # post data
                                            response = requests.post(
                                                '%s/%s' % (secrets.MMS_API, 'work'),
                                                headers={
                                                    'Content-Type': 'application/json',
                                                    'Authorization': 'Bearer %s' % secrets.MMS_API_TOKEN},
                                                data=json.dumps(thedata)
                                            )
                                            status = response.status_code
                                            logger.info('STATUS: %s' % status)
                                            if status == 201:
                                                response_json = json.loads(response.content.decode("utf-8"))
                                                # logger.info(response_json.get('work'))
                                                if response_json.get('message'):
                                                    logger.info(response_json.get('message'))
                                            else:
                                                logger.error('ERROR: %s: %s' % (status, response.content.decode("utf-8")))

                                        except requests.exceptions.ConnectionError as e:
                                            logger.error(e)

                                        sources.set('orcid:%s' % work_sum.get('put-code'), str(datetime.datetime.now())[:-3])
            else:
                logger.error('user response not valid for %s' % orcid_id)
        else:
            logger.error('user %s not found' % orcid_id)

    except requests.exceptions.ConnectionError as e:
        logger.error(e)


# ---- MMS to ORCID plattform ---- #
def sync_mms_to_orcid(orcid_id=''):
    if orcid_id:
        try:
            response = requests.get('%s/%s/%s' % (secrets.MMS_API, 'user', orcid_id),
                                    headers={'Accept': 'application/json',
                                             'Authorization': 'Bearer %s' % secrets.MMS_API_TOKEN},
                                    )
            status = response.status_code
            if status == 200:
                user = json.loads(response.content.decode('utf8'))
                if user:
                    if '/activities/update' in user.get('orcidscopes'):
                        # add new records to orcid
                        records = get_new_records(affiliation=user.get('affiliation'), orcid_id=orcid_id)
                        orcid_add_records(affiliation=user.get('affiliation'), orcid_id=orcid_id,
                                          access_token=user.get('orcidaccesstoken'), works=records)
                        # update records in orcid
                        records = get_updated_records(affiliation=user.get('affiliation'), orcid_id=orcid_id)
                        orcid_update_records(affiliation=user.get('affiliation'), orcid_id=orcid_id,
                                             access_token=user.get('orcidaccesstoken'), works=records)
                else:
                    logger.error('user response not valid for %s' % orcid_id)
            else:
                logger.error('user %s not found' % orcid_id)

        except requests.exceptions.ConnectionError as e:
            logger.error(e)


###################################################

if __name__ == "__main__":

    sources = redis.StrictRedis(host=secrets.REDIS_SOURCE_IDS_HOST,
                                port=secrets.REDIS_SOURCE_IDS_PORT,
                                db=secrets.REDIS_SOURCE_IDS_DB)

    print('size of source directory: %s' % sources.dbsize())
    # sources.flushdb()
    # print('size of source directory: %s' % sources.dbsize())

    if secrets.IDS_FOR_SYNC_TO_ORCID:
        for item in secrets.IDS_FOR_SYNC_TO_ORCID:
            sync_mms_to_orcid(orcid_id=item)

    if secrets.IDS_FOR_SYNC_TO_MMS:
        for item in secrets.IDS_FOR_SYNC_TO_MMS:
            sync_orcid_to_mms(orcid_id=item)

    print('size of source directory: %s' % sources.dbsize())

