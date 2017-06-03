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
import orcid
import simplejson as json
import redis
import requests
from requests import RequestException
from urllib import parse

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

# ---- ORCID functions ---- #
# see also: https://github.com/ORCID/ORCID-Source/tree/master/orcid-model/src/main/resources/record_2.0


def orcid_user_info(affiliation='', orcid_id='', access_token=''):

    if affiliation:
        info = {}
        info.setdefault('orcid', orcid_id)

        sandbox = secrets.ORCID_API_DATA.get(affiliation).get('sandbox')
        client_id = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_id')
        client_secret = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_secret')
        if not sandbox:
            client_id = secrets.ORCID_API_DATA.get(affiliation).get('client_id')
            client_secret = secrets.ORCID_API_DATA.get(affiliation).get('client_secret')

        api = orcid.MemberAPI(client_id, client_secret, sandbox=sandbox)

        try:
            # get public_info from orcid
            public_info = api.read_record_public(orcid_id=orcid_id, request_type='person', token=access_token)
            return public_info

        except RequestException as e:
            logging.error('ORCID-ERROR: %s' % e.response.text)

    else:
        logging.error('Bad request: affiliation has no value!')


def orcid_add_records(affiliation='', orcid_id='', access_token='', works=None):
    if works is None:
        works = {}

    if works:

        if affiliation:
            sandbox = secrets.ORCID_API_DATA.get(affiliation).get('sandbox')
            client_id = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_id')
            client_secret = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_secret')
            if not sandbox:
                client_id = secrets.ORCID_API_DATA.get(affiliation).get('client_id')
                client_secret = secrets.ORCID_API_DATA.get(affiliation).get('client_secret')

            api = orcid.MemberAPI(client_id, client_secret, sandbox=sandbox)

            for record_id in works.keys():
                # logging.info('work: %s' % work)

                work = works.get(record_id)[0]
                # print(work)

                try:
                    put_code = api.add_record(orcid_id=orcid_id, token=access_token, request_type='work',
                                              data=work)

                    if put_code:
                        orcid_record = api.read_record_member(orcid_id=orcid_id, request_type='work',
                                                              token=access_token, put_code=put_code)
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
                            logging.error(e)
                except RequestException as e:
                    logging.error('ORCID-ERROR: %s' % e.response.text)
        else:
            logging.error('Bad request: affiliation has no value!')


def orcid_update_records(affiliation='', orcid_id='', access_token='', works=None):
    if works is None:
        works = {}

    if works:

        if affiliation:
            sandbox = secrets.ORCID_API_DATA.get(affiliation).get('sandbox')
            client_id = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_id')
            client_secret = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_secret')
            if not sandbox:
                client_id = secrets.ORCID_API_DATA.get(affiliation).get('client_id')
                client_secret = secrets.ORCID_API_DATA.get(affiliation).get('client_secret')

            api = orcid.MemberAPI(client_id, client_secret, sandbox=sandbox)

            for record_id in works.keys():
                # logging.info('work: %s' % work)

                work = works.get(record_id)[0]
                # print(json.dumps(work, indent=4))

                try:
                    put_code = int(record_id)
                    api.update_record(orcid_id=orcid_id, token=access_token,
                                      request_type='work', put_code=put_code, data=work)

                    orcid_record = api.read_record_member(orcid_id=orcid_id, request_type='work',
                                                          token=access_token, put_code=put_code)
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
                        logging.error(e)

                except RequestException as e:
                    logging.error('ORCID-ERROR: %s' % e.response.text)

        else:
            logging.error('Bad request: affiliation has no value!')


def orcid_add_external_id(affiliation='', orcid_id='', access_token='', external_id=None):

    put_code = ''

    if affiliation:
        sandbox = secrets.ORCID_API_DATA.get(affiliation).get('sandbox')
        client_id = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_id')
        client_secret = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_secret')
        if not sandbox:
            client_id = secrets.ORCID_API_DATA.get(affiliation).get('client_id')
            client_secret = secrets.ORCID_API_DATA.get(affiliation).get('client_secret')

        api = orcid.MemberAPI(client_id, client_secret, sandbox=sandbox)

        try:

            logging.info('external_id: %s' % external_id)

            put_code = api.add_record(orcid_id=orcid_id, token=access_token, request_type='external-identifiers',
                                      data=external_id)

            # get info from orcid again
            info = api.read_record_member(orcid_id=orcid_id, request_type='external-identifiers', token=access_token)
            logging.info('info: %s' % info)

        except RequestException as e:
            logging.error('ORCID-ERROR: %s' % e.response.text)
    else:
        logging.error('Bad request: affiliation has no value!')

    return put_code


def orcid_read_works(affiliation='', orcid_id='', access_token=''):

    works = []

    if affiliation:
        sandbox = secrets.ORCID_API_DATA.get(affiliation).get('sandbox')
        client_id = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_id')
        client_secret = secrets.ORCID_API_DATA.get(affiliation).get('sandbox_client_secret')
        if not sandbox:
            client_id = secrets.ORCID_API_DATA.get(affiliation).get('client_id')
            client_secret = secrets.ORCID_API_DATA.get(affiliation).get('client_secret')

        api = orcid.MemberAPI(client_id, client_secret, sandbox=sandbox)

        try:

            info = api.read_record_member(orcid_id=orcid_id, request_type='activities', token=access_token)
            # logging.info('info: %s' % info)
            works = info.get('works').get('group')

        except RequestException as e:
            logging.error('ORCID-ERROR: %s' % e.response.text)

    else:
        logging.error('Bad request: affiliation has no value!')

    return works


# ---- MMS functions ---- #

def get_new_records(affiliation='', query='*:*'):

    query_string = 'q=%s AND -orcid_put_code:[\'\' TO *]' % query
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
                logging.info('No records found for query: %s' % query)
        else:
            logging.info('No records found for query: %s' % query)

    except requests.exceptions.ConnectionError as e:
        logging.error(e)

    return orcid_records


def get_updated_records(affiliation='', query='*:*'):

    query_string = 'q=%s AND orcid_put_code:[\'\' TO *]' % query
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
                logging.info('No records found for query: %s' % query)
        else:
            logging.info('No records found for query: %s' % query)

    except requests.exceptions.ConnectionError as e:
        logging.error(e)

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


# ---- ORCID plattform to HB 2 ---- #
def sync_orcid_to_hb(orcid_id=''):
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
                                            logging.error(e)
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
                                            logging.error(e)

                                        sources.set('orcid:%s' % work_sum.get('put-code'), str(datetime.datetime.now())[:-3])
            else:
                logging.error('user response not valid for %s' % orcid_id)
        else:
            logging.error('user %s not found' % orcid_id)

    except requests.exceptions.ConnectionError as e:
        logging.error(e)


# ---- HB 2 to ORCID plattform ---- #
def sync_hb_to_orcid(orcid_id=''):
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
                        records = get_new_records(affiliation=user.get('affiliation'),
                                                  query='orcid:%s' % orcid_id)
                        orcid_add_records(affiliation=user.get('affiliation'), orcid_id=orcid_id,
                                          access_token=user.get('orcidaccesstoken'), works=records)
                        # update records in orcid
                        records = get_updated_records(affiliation=user.get('affiliation'),
                                                      query='orcid:%s' % orcid_id)
                        orcid_update_records(affiliation=user.get('affiliation'), orcid_id=orcid_id,
                                             access_token=user.get('orcidaccesstoken'), works=records)
                else:
                    logging.error('user response not valid for %s' % orcid_id)
            else:
                logging.error('user %s not found' % orcid_id)

        except requests.exceptions.ConnectionError as e:
            logging.error(e)


###################################################

if __name__ == "__main__":

    sources = redis.StrictRedis(host=secrets.REDIS_SOURCE_IDS_HOST,
                                port=secrets.REDIS_SOURCE_IDS_PORT,
                                db=secrets.REDIS_SOURCE_IDS_DB)

    print('size of source directory: %s' % sources.dbsize())

    # sync ORCID works to HB2
    sync_orcid_to_hb(orcid_id='0000-0002-5643-8074')

    print('size of source directory: %s' % sources.dbsize())


    # sync HB2 works to ORCID
    # sync_hb_to_orcid(orcid_id='0000-0002-7349-3032')
