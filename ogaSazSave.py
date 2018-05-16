# coding: utf-8

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter
from java.lang import RuntimeException
from java.lang import String
from java.net import URL

from javax.swing import JMenuItem
from java.util import ArrayList
from java.awt.event import ActionListener

import tempfile
import shutil
import os
import base64
import struct
from datetime import datetime as dt

import binascii

class BurpExtender(IBurpExtender):
    
    def	registerExtenderCallbacks(self, callbacks):
        # set our extension name
        self.callbacks = callbacks
        self.callbacks.setExtensionName("OgaSazSave")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        saveSazhandler = RightClickHandler(self.callbacks)
        callbacks.registerContextMenuFactory(saveSazhandler)
        
        self.stdout.println("OgaSazSave v0.9 Load OK!!")

class RightClickHandler(IContextMenuFactory):

    def __init__(self, callbacks):
        self.callbacks = callbacks

    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        item = JMenuItem("Send to OgaSazSave")
        item.addActionListener(self.SaveSazHandler(self.callbacks,invocation))
        items = ArrayList()
        items.add(item)
        return items

    class SaveSazHandler(ActionListener):

        def __init__(self, callbacks, invocation):
            self.callbacks = callbacks
            self.invocation = invocation

        def actionPerformed(self, actionEvent):
            httpReqReslist = self.invocation.getSelectedMessages()
            if (httpReqReslist.count < 0):
                return

            makeSaz(self.callbacks.getHelpers(),httpReqReslist)

#saz
contentsTypesHtml = '''<?xml version="1.0" encoding="utf-8" ?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="htm" ContentType="text/html" />
<Default Extension="xml" ContentType="application/xml" />
<Default Extension="txt" ContentType="text/plain" />
</Types>'''

indexheader = '''<html><head><style>body,thead,td,a,p{font-family:verdana,sans-serif;font-size: 10px;}</style></head><body><table cols=12><thead><tr><th>&nbsp;</th><th>#</th><th>Result</th><th>Protocol</th><th>Host</th><th>URL</th><th>Body</th><th>Caching</th><th>Content-Type</th><th>Process</th><th>Comments</th><th>Custom</th></tr></thead><tbody>'''

indexbodybase = '''<tr><td><a href='raw\{index}_c.txt'>C</a>&nbsp;<a href='raw\{index}_s.txt'>S</a>&nbsp;<a href='raw\{index}_m.xml'>M</a></td><td>{number}</td><td>{result}</td><td>{protocol}</td><td>{host}</td><td>{url}</td><td>body</td><td>{caching}</td><td>{contentType}</td><td>{process}</td><td>{comments}</td><td>{custom}</td></tr>'''

indexfooter = '</tbody></table></body></html>'

basemtext = '''<?xml version="1.0" encoding="utf-8"?>
<Session SID="1" BitFlags="81">
  <SessionTimers ClientConnected="2018-03-31T12:43:33.0112985+09:00" ClientBeginRequest="2018-03-31T12:43:33.0122988+09:00" GotRequestHeaders="2018-03-31T12:43:33.0122988+09:00" ClientDoneRequest="2018-03-31T12:43:33.0122988+09:00" GatewayTime="0" DNSTime="175" TCPConnectTime="160" HTTPSHandshakeTime="1905" ServerConnected="2018-03-31T12:43:33.3532965+09:00" FiddlerBeginRequest="2018-03-31T12:43:35.2584025+09:00" ServerGotRequest="2018-03-31T12:43:35.2584025+09:00" ServerBeginResponse="2018-03-31T12:43:35.4505154+09:00" GotResponseHeaders="2018-03-31T12:43:35.4505154+09:00" ServerDoneResponse="2018-03-31T12:43:35.4515157+09:00" ClientBeginResponse="2018-03-31T12:43:35.4515157+09:00" ClientDoneResponse="2018-03-31T12:43:35.4515157+09:00" />
  <PipeInfo />
  <SessionFlags>
    <SessionFlag N="x-responsebodytransferlength" V="528" />
    <SessionFlag N="x-egressport" V="54077" />
    <SessionFlag N="x-autoauth" V="(default)" />
    <SessionFlag N="x-clientport" V="0" />
    <SessionFlag N="x-clientip" V="127.0.0.1" />
    <SessionFlag N="x-builder-maxredir" V="3" />
    <SessionFlag N="x-hostip" V="127.0.0.1" />
  </SessionFlags>
  </Session>'''

###
def makeSaz(helpers,httpReqReslist):

    tempd = TemporaryDirectory()

    with tempd as rootdir:        
        rowdir = os.path.join(rootdir, 'raw')
        os.mkdir(rowdir)

        indexHtmlbody = ''

        #raw loop
        for cnt,httpReqRes in enumerate(httpReqReslist):            
            with open(os.path.join(rowdir, str(cnt) + "_c.txt"), "wb") as f:
                newRequestList = chageRequestLinePathtoUrl(helpers,httpReqRes)

                for req in newRequestList:            
                    f.write(struct.pack("B", req))
                    
            with open(os.path.join(rowdir, str(cnt) + "_m.xml"), "w") as f:
                f.write(basemtext)

            with open(os.path.join(rowdir, str(cnt) + "_s.txt"), "wb") as f:
                for res in httpReqRes.getResponse():            
                    f.write(struct.pack("B", res))

            ## _index.html
            resInfo = helpers.analyzeRequest(httpReqRes.getResponse())

            indexHtmlbody = indexHtmlbody + indexbodybase.format(index=str(cnt),number=str(cnt),result=str(httpReqRes.getStatusCode()),protocol=httpReqRes.getHttpService().getProtocol().upper(),host=httpReqRes.getHttpService().getHost(),url=httpReqRes.getUrl().getPath(),caching='//todo',contentType='//todo',process='',comments='',custom='')

        # _index/htm
        with open(os.path.join(rootdir,"_index.htm"), "w") as f:
            f.write(indexheader + indexHtmlbody + indexfooter)

        # [Content_typs].xml
        with open(os.path.join(rootdir, "[Content_typs].xml"), "w") as f:
            f.write(contentsTypesHtml)
        
        #zip
        tdatetime = dt.now().strftime('%Y%m%d_%H%M%S')
        tmpfileName = tdatetime
        tmpfileType = 'zip'
        targetPath = 'c:\\tmp\\' + tmpfileName
        shutil.make_archive(targetPath, tmpfileType, root_dir=rootdir)

        #copy
        sazFilePath = targetPath + '.saz'
        shutil.copy(targetPath + '.' + tmpfileType, sazFilePath)

        #delete file
        zipFilePath = targetPath + '.zip'
        os.remove(zipFilePath)        

def chageRequestLinePathtoUrl(helpers,httpReqRes):
    requestbytelist = httpReqRes.getRequest()

    requestString = ''
    requestPythonByteList = []

    for b in requestbytelist:
        requestString = requestString + chr(b)
        requestPythonByteList.append(b)

    hrsp = HttpRequestRawStringParser(requestString)
    method = hrsp.getRequestMethod()
    reqpath = hrsp.getRequestPath()
    version = hrsp.getRequestHttpVersion()

    if reqpath.startswith('/') == False:
        return

    protocol = httpReqRes.getHttpService().getProtocol()
    host = httpReqRes.getHttpService().getHost()
    port = httpReqRes.getHttpService().getPort()

    if port <> 80 and port <> 443:
        host = host + ":" + port

    newRequestLine = method + " " + protocol + "://" + host + reqpath + " " + version

    index = requestPythonByteList.index(13)
    del(requestPythonByteList[0:index])

    newRequestLineList = list(newRequestLine)

    newRequestLineByteList = []
    for b in newRequestLineList:
        newRequestLineByteList.append(ord(b))
    
    return newRequestLineByteList + requestPythonByteList

# ref https://qiita.com/hira_physics/items/aa7c6f612ff0a9db7f01
class TemporaryDirectory(object):
    def __init__(self, suffix="", prefix="tmp", dir=None):
        self.__name = tempfile.mkdtemp(suffix, prefix, dir)

    def __enter__(self):
        return self.__name

    def __exit__(self, exc, value, tb):
        self.cleanup()

    @property
    def name(self):
        return self.__name

    def cleanup(self):
        shutil.rmtree(self.__name)

# ref https://github.com/OgaworldEX/HttpRequestRawStringParser/blob/master/HttpRequestRawStringParser.py
class HttpRequestRawStringParser:

    delimiter = '\r\n'
    requestRawString = ''
    requestLine = ''

    def __init__(self, requestRawString,delimiter='\r\n'):
        self.requestRawString = requestRawString
        self.delimiter = delimiter
        self.requestLine = self.getRequestLine()

    def getRequestLine(self):
        index = self.requestRawString.find(self.delimiter)
        self.requestLine = self.requestRawString[0:index]
        return self.requestLine

    def getRequestMethod(self):
        index = self.requestLine.find(' ')
        return self.requestLine[0:index]

    def getRequestPath(self):
        findex = self.requestLine.find(' ')
        bindex = self.requestLine.rfind(' ')
        return self.requestLine[findex + 1:bindex]

    def getRequestHttpVersion(self):
        index = self.requestLine.rfind(' ')
        return self.requestLine[index + 1:len(self.requestLine)]

    def getHeadderArray(self):
        index = self.requestRawString.find(self.delimiter + self.delimiter)
        headders = self.requestRawString[0:index].split(self.delimiter)
        del headders[0]
        return headders

    def getRequestBodyString(self):
        index = self.requestRawString.rfind(self.delimiter + self.delimiter)
        return self.requestRawString[index+2:len(self.requestRawString)]

    def getUrlParamString(self):
        return self.requestLine.split(' ')[1]

    def getUrlParamDic(self):
        requestPath = self.getUrlParamString()
        index = requestPath.rfind('?')
        param = requestPath[index + 1:len(requestPath)]

        ret = {}
        for keyValue in param.split('&'):
            tmp = keyValue.split('=')
            if len(tmp) > 1:
                ret[tmp[0]] = tmp[1]

        return ret

    def getHeadderDic(self):
        headders = self.getHeadderArray()
        ret = {}
        for headder in headders:
            tmp = headder.split(': ')
            if len(tmp) > 1:
                ret[tmp[0]] = tmp[1]

        return ret

    def getCookieDic(self):
        headderDic = self.getHeadderDic()

        for key in headderDic.keys():
            if key.lower() == 'cookie':
                cookiekey = key
                break;

        cookieLine =headderDic[cookiekey]
        cookieArray = cookieLine.split(';')

        ret = {}
        for cookie in cookieArray:
            cookie.strip()
            tmp = cookie.split('=')
            if len(tmp) > 1:
                ret[tmp[0]] = tmp[1]

        return ret

    def getBodyParamDic(self):
        bodyString = self.getRequestBodyString()

        ret = {}
        for keyValue in bodyString.split('&'):
            tmp = keyValue.split('=')
            if len(tmp) > 1:
                ret[tmp[0]] = tmp[1]

        return ret


