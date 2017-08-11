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

LOGFILE = 'log/orcid_sync.log'

# ---- ORCID CONFIG ---- #
ORCID_API_DATA = {
    'tudo': {
        'sandbox': True,
        'sandbox_client_id': '',
        'sandbox_client_secret': '',
        'client_id': '',
        'client_secret': '',
        'redirect_uri': ''
    }
    # multiple configurations are possible
}

ORCID_SCOPES = [
    '/read-limited',
    '/activities/update',
    '/orcid-bio/update',
]

# ---- HB2 API ---- #
MMS_API = 'http://localhost:5007/api'
MMS_API_TOKEN = ''

# ---- SOURCE ID LIST ---- #
REDIS_SOURCE_IDS_URL = 'redis://localhost:6379/4'
REDIS_SOURCE_IDS_HOST = 'localhost'
REDIS_SOURCE_IDS_PORT = 6379
REDIS_SOURCE_IDS_DB = 4

# ---- IDs for SYNC JOBS ---- #
IDS_FOR_SYNC_TO_MMS = []
IDS_FOR_SYNC_TO_ORCID = []
