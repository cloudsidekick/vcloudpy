#########################################################################
# Copyright 2013 Cloud Sidekick
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#########################################################################

import urllib2
import httplib
import base64
import re
import time

try:
    import xml.etree.cElementTree as ET
except (AttributeError, ImportError):
    import xml.etree.ElementTree as ET

try:
    ET.ElementTree.iterfind
except AttributeError as ex:
    del(ET)
    import etree.ElementTree as ET

      
def _xml_del_ns(xml):
    """A helper function that strips vcloud namespaces from xml text.
    This is used because sometimes the vcloud namespace is used, other 
    times it is not. Befuddling.""" 

    try:
        p = re.compile("xmlns=*[\"\"][^\"\"]*[\"\"]")
        allmatches = p.finditer(xml)
        for match in allmatches:
            xml = xml.replace(match.group(), "")
    except Exception as e:
        raise Exception(e)
    if "xmlns:vcloud" in xml:
        xml = xml.replace("vcloud:", "")
    xml = xml.replace(" xmlns:vcloud=\"http://www.vmware.com/vcloud/v1.5\"", "")
    return xml

def get_node_values(xml, path, attribs=[], elems=[], other=""):
    """Given an xml string and path, returns a list of dictionary objects.

    Arguments:
    xml -- a string of properly formatted xml
    path -- an Xpath path. 
            See http://docs.python.org/2/library/xml.etree.elementtree.html#supported-xpath-syntax
    attribs -- an optional list of xml node attribute names to retrieve the values for. 
            "*" will retrieve all attributes per node found.
    elems -- an optional list of xml child elements to retrieve the text value for.
            "*" will retrieve all child elements per node found.
    other -- if the attribute or element is not found, return this value (e.g. "" or None)

    Example:
    
    print get_node_values(z, "./NetworkConnection", elems=["MACAddress", "IpAddress"], 
        attribs=["network", "needsCustomization", "aaaaaaaa"], other=None)

    Might return a list of two interfaces with the following dictionary values:

    [{'needsCustomization': 'false', 'aaaaaaaa': None, 'IpAddress': '212.54.150.58', 'network': 'Direct Internet connection', 'MACAddress': '00:50:56:01:02:eb'}, {'needsCustomization': 'false', 'aaaaaaaa': None, 'IpAddress': '212.54.150.82', 'network': 'Direct Internet connection', 'MACAddress': '00:50:56:01:02:e7'}]
    """

    result = []
    root = ET.fromstring(_xml_del_ns(xml))
    if not path.startswith("./"):
        path = "./" + path
    nodes = root.findall(path)

    for n in nodes:
        node_result = {}
        if "*" in attribs:
            node_result = n.attrib
            # we don't care about the rest of the list, move on to elems
        else:
            for a in attribs:
                if a in n.attrib.keys():
                    node_result[a] = n.attrib.get(a)
                else:
                    node_result[a] = other
        if "*" in elems:
            for e in n:
                node_result[e.tag] = e.text
                # we don't care about the rest of the list, move on to the next node
        else:
            for e in elems:
                node_result[e] = n.findtext(e, other)
        result.append(node_result)
    del(root)
    # don't forget: result will be a list, empty if path is not found
    return result 

class VCloudConn():
    """Example:
    conn = vcloudpy.VCloudConn(user, password, endpoint, debug=True)
    """

    def __init__(self, user, password, endpoint, protocol="https", api_version="1.5", 
        path="/api", timeout=30, debug=False):
        """Initiallizes the VCloudConn class.

        Will automatically use parameters and establish connection to vCloud endpoint.
        
        Arguments:
        user -- vCloud userid in the form of user@orgid
        password -- vCloud user's password
        endpoint -- vCloud server endpoint, e.g. iad.vcloudservice.vmware.com
        protocol -- optional, http or https (default), most likely https
        api_version -- optional, usually either 5.1 (default) or 1.5
        path -- optional, api uri path, most likely don't change
        timeout -- optional, timeout in seconds for all http connections with vCloud, default 30
        debug -- optional, prints html responses from vCloud, True or False (default)
        """
        
        self.api_version = api_version
        self.timeout = timeout
        self.debug = debug
        self.base_url = "%s://%s%s" % (protocol.lower(), endpoint, path)

        # ok, we should be able to login now
        self._login(user, password)

    
    def _login(self, user, password):
        """Handles login duties, retrieves authorization token"""

        if self.api_version is None:
            self.api_version = self._determine_version(self.base_url + "/versions")
        auth_url = self.base_url + "/sessions"
        req = urllib2.Request(auth_url)
        auth = "Basic " + base64.urlsafe_b64encode("%s:%s" % (user, password))
        req.add_header("Authorization", auth)
        req.get_method = lambda: "POST"

        # this should be in a try / except with more specific error messages
        result = self._send_request(req)
        self.auth_token = result.info().getheader("x-vcloud-authorization")

      
    def _determine_version(self, url):

        req = urllib2.Request(url)
        response = self._send_request(req)
        xml = _xml_del_ns(response.read())
        versions = get_node_values(xml, "VersionInfo", elems=["Version"])
        lv = []
        for v in versions:
            lv.append(v["Version"])
        lv.sort()
        lv.reverse()
        return lv[0] 
            


    def _make_request(self, url, verb, data=None, type=None, timeout=None):
        """Constructs the vCloud api request to send"""

        url = url.replace(" ", "+")
        req = urllib2.Request(url)
        req.add_header("x-vcloud-authorization", self.auth_token)
        if type:
            req.add_header("Content-Type", type)
        req.get_method = lambda: verb
        if data:
            req.add_data(data)
        response = self._send_request(req, timeout=timeout)
        return response.read()

    def _send_request(self, req, timeout=None):
        """Sends the request and handles errors"""

        req.add_header("Accept", "application/*+xml;version=%s" % self.api_version)
        if self.debug:
            print("vCloud api version being used: %s" % (self.api_version))
        reattempt = True
        attempt = 1
        reattempt_http_codes = [401]
        delay = 1
        attempts_allowed = 10
        if not timeout:
            timeout = self.timeout 
        while reattempt is True and attempt <= attempts_allowed:
            try:
                response = urllib2.urlopen(req, timeout=timeout)
            except urllib2.HTTPError, e:
                if e.code in reattempt_http_codes and attempt < attempts_allowed:
                    print("HTTPError, will reattempt = %s, %s, %s\n%s" % (str(e.code), e.msg, e.read(), req.get_full_url()))
                    attempt += 1
                    time.sleep(delay)
                    continue
                else:
                    raise Exception("HTTPError = %s, %s, %s\n%s" % (str(e.code), e.msg, e.read(), req.get_full_url()))
            except urllib2.URLError, e:
                raise Exception("URLError = %s\n%s" % (str(e.reason), req.get_full_url()))
            except httplib.NotConnected, e:
                raise e
            except httplib.InvalidURL, e:
                raise e
            except httplib.UnknownProtocol, e:
                raise e
            except httplib.UnknownTransferEncoding, e:
                raise e
            except httplib.UnimplementedFileMode, e:
                raise e
            except httplib.IncompleteRead, e:
                raise e
            except httplib.ImproperConnectionState, e:
                raise e
            except httplib.BadStatusLine, e:
                print req.get_full_url()
                raise Exception("BadStatusLine: The server responded with an unknown status or an empty response.  Possible causes: request was 'https' but the server is 'http', or vice versa.\n%s" % (str(e)))
            except httplib.CannotSendRequest, e:
                raise e
            except httplib.CannotSendHeader, e:
                raise e
            except httplib.ResponseNotReady, e:
                raise e
            except httplib.HTTPException, e:
                raise e
            except Exception:
                import traceback
                raise Exception("generic exception: " + traceback.format_exc())
            else:
                # got here, request was successful, break out
                reattempt = False

        if self.debug:
            print(response.info())
            r = response.read()
            print(r)

        return response

    
    def logout(self):
        """Handles the logout duties"""

        self.make_method_request("session", "DELETE")
        self.auth_token = None


    def make_href_request_path(self, href, verb="GET", data=None, type=None, timeout=None):
        """Used to retrieve an object using a full path"""

        return self._make_request(href, verb, data, type, timeout=timeout)

    def make_method_request(self, method, verb="GET", timeout=None):
        """Used to make a method request."""

        full_url = self.base_url + "/" + method
        return self._make_request(full_url, verb, timeout=timeout)


