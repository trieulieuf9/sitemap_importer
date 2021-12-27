from burp import IBurpExtender
from burp import IHttpService
from burp import IHttpRequestResponse
import urlparse
import os


class BurpExtender(IBurpExtender):

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.callbacks.setExtensionName("Sitemap Importer");
		self.helper = callbacks.getHelpers()

		root_folder = os.getcwd()
		sitemap_folder_path = os.path.join(root_folder, "source_sitemap")

		if not self.ensureSiteMapFolder(sitemap_folder_path):
			return

		parser = XMLParser()
		for file in os.listdir(sitemap_folder_path):
			if file.endswith(".xml"):
				file_path = os.path.join(sitemap_folder_path, file)
				print("Begin parsing {}".format(file))
				parser.parse(file_path)
				for item in parser.getItems():
					self.addToSiteMap(item[0], item[1], item[2])
				print("Finish parsing: {}, {} items added".format(file, len(parser.getItems())))

		print("done")
		return


	def addToSiteMap(self, url, request, response):
		"""
		request: the whole request in base64 
		response: the whole response in base64
		url: url in string. Don't need path or query
		"""
		requestResponse = HttpRequestResponse(self.helper.base64Decode(request), self.helper.base64Decode(response), HttpService(url), "", "")

		self.callbacks.addToSiteMap(requestResponse)


	def ensureSiteMapFolder(self, sitemap_folder_path):
		if not os.path.exists(sitemap_folder_path):
			print("Cannot find folder {}".format(sitemap_folder_path))
			return False

		if len([f for f in os.listdir(sitemap_folder_path) if f.endswith(".xml")]) == 0:
			print("no sitemap xml file found in {}".format(sitemap_folder_path))
			return False

		return True


class XMLParser():
	"""
	Shitty XMLparser that only looking for certain tags. After go through a XML file. It returns an list of list containing the following data
	[request_base64, response_base64, url_string, color, comment]

	Because this is a shitty parser, It doesn't support comment, because specific characters, such as "<", ">" will break it (I guess).
	If you really want comment in your sitemap. Raise an issue.
	"""

	def __init__(self):
		self.items = []

	def getItems(self):
		self.cleanUpItems()
		return self.items

	def cleanUpItems(self):
		"""
		Value inside item are wrapped with <![CDATA[ ... ]], this function remove it
		"""
		for item in self.items:
			for i, value in enumerate(item):
				item[i] = value.lstrip("<![CDATA[").rstrip("]]>")

	def parse(self, file_path):
		self.items = []

		def _get_char(string, index):
			if len(string) > index:
				return string[index]
			else:
				return ""

		with open(file_path) as file:
			xml_content = file.read()

		# Don't jugde, I only spend 90 minutes on this
		is_tag = False
		tag_name = ""
		tag_content = ""
		start_tag = False
		end_tag = False
		item = [None] * 3
		for i, char in enumerate(xml_content):
			next_char = _get_char(xml_content, i+1)
			next_next_char = _get_char(xml_content, i+2)
			if char == "<" and next_char != "!":
				is_tag = True
				tag_name = ""
				start_tag = False
				end_tag = False

			if is_tag:
				tag_name += char

			if start_tag:
				tag_content += char

			if (char == ">" and next_char != "<") or (char == ">" and next_char == "<" and next_next_char == "!"):
				is_tag = False
				if tag_name.startswith("</"):
					end_tag = True
				else:
					start_tag = True
					tag_content = ""

			if end_tag:
				# IMPROVE: add support for highlight and comment.
				if tag_name == "</url>":
					item[0] = tag_content
				elif tag_name == "</request>":
					item[1] = tag_content
				elif tag_name == "</response>":
					item[2] = tag_content
				elif tag_name == "</item>":
					self.items.append(item)
					item = [None] * 3
					print(len(self.items))

				end_tag = False


class HttpService(IHttpService):
	"""
	copied from https://github.com/modzero/burp-ResponseClusterer/blob/master/ResponseClusterer.py

	"""

	def __init__(self, url):
		x = urlparse.urlparse(url)
		if x.scheme in ("http", "https"):
			self._protocol = x.scheme
		else:
			raise ValueError()
		self._host = x.hostname
		if not x.hostname:
			self._host = ""
		self._port = None
		if x.port:
			 self._port = int(x.port)
		if not self._port:
			if self._protocol == "http":
				self._port = 80
			elif self._protocol == "https":
				self._port = 443

	def getHost(self):
		return self._host

	def getPort(self):
		return self._port

	def getProtocol(self):
		return self._protocol

	def __str__(self):
		return "protocol: {}, host: {}, port: {}".format(self._protocol, self._host, self._port)


class HttpRequestResponse(IHttpRequestResponse):

	def __init__(self, request, response, httpService, cmt, color):
		self.setRequest(request)
		self.setResponse(response)
		self.setHttpService(httpService)
		self.setHighlight(color)
		self.setComment(cmt)

	def getRequest(self):
		return self.req

	def getResponse(self):
		return self.resp

	def getHttpService(self):
		return self.serv

	def getComment(self):
		return self.cmt

	def getHighlight(self):
		return self.color

	def setHighlight(self, color):
		self.color = color

	def setComment(self, cmt):
		self.cmt = cmt

	def setHttpService(self, httpService):
		self.serv = httpService

	def setRequest(self, message):
		self.req = message

	def setResponse(self, message):
		self.resp = message
