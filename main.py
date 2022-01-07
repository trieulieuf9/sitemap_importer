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

		
		for file in os.listdir(sitemap_folder_path):
			if file.endswith(".xml"):
				file_path = os.path.join(sitemap_folder_path, file)

				parser = XMLParser(file_path)
				parser.parse()
				parser.printSummary()

				for item in parser.getItems():
					self.addToSiteMap(item[0], item[1], item[2])

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

	def __init__(self, file_path, verbose=True):
		self.items = []
		self.skip_items = []
		self.response_len_limit = 2000000
		self.verbose = verbose
		self.file_path = file_path
		self.file_name = file_path.split("/")[-1]

	def getItems(self):
		return self.items

	def getSkipItems(self):
		return self.skip_items

	def printSummary(self):
		print("------------")
		print("- Summary: {}".format(self.file_name))
		print("+ {} items successfully parsed".format(len(self.items)))

		if len(self.skip_items) > 0:
			print("+ {} items skipped due to response size > {} bytes".format(len(self.skip_items), self.response_len_limit))
			for item in self.skip_items:
				print("+++ skipped item: {}, reponse size: {}".format(item[0], item[1]))

	def _print(self, message, params):
		if self.verbose:
			print(message.format(*params))

	def _get_char(self, string, index):
			if len(string) > index:
				return string[index]
			else:
				return ""

	def parse(self):
		self._print("Begin parsing {}", [self.file_name])

		with open(self.file_path) as file:
			xml_content = file.read()

		# Don't jugde, I only spend 90 minutes on this
		# 150 minutes now
		# 170 minutes now
		is_tag = False
		tag_name = ""
		tag_content = []
		start_tag = False
		end_tag = False
		skip = False  # true when response is too big
		item = [None] * 3
		item_count = 0
		for i, char in enumerate(xml_content):

			if char == "<" and self._get_char(xml_content, i+1) != "!":
				is_tag = True
				tag_name = ""
				start_tag = False
				end_tag = False

			if is_tag:
				tag_name += char

			if start_tag and not skip:
				tag_content.append(char)

			# if (char == ">" and next_char != "<") or (char == ">" and next_char == "<" and next_next_char == "!"):
			if char == ">":
				next_char = self._get_char(xml_content, i+1)
				next_next_char = self._get_char(xml_content, i+2)
				if next_char != "<" or (next_char == "<" and next_next_char == "!"):
					is_tag = False
					if tag_name.startswith("</"):
						end_tag = True
					else:
						start_tag = True
						tag_content = []

			if end_tag:
				value = "".join(tag_content).lstrip("<![CDATA[").rstrip("]]>")

				if tag_name == "</url>":
					item[0] = value
					item_count += 1
					self._print("- {}. url: {}", [item_count, value])
				elif tag_name == "</request>":
					item[1] = value
					self._print("+ request: {}", [len(value)])
				elif tag_name == "</response>":
					item[2] = value
					self._print("+ response: {}", [len(value)])
				elif tag_name == "</responselength>":
					if int(value) > self.response_len_limit:
						# skip this item if response size > 2MB
						skip = True
						self.skip_items.append((item[0],int(value)))
						self._print("+ Skip this item because response size is too large: {} bytes", (value))
				elif tag_name == "</item>":
					if not skip:
						self.items.append(item)
					item = [None] * 3
					skip = False

				end_tag = False
		self._print("Finish parsing: {}", [self.file_name])


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
