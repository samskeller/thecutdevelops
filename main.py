#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import re
import os
import jinja2
import json
import hashlib
import hmac
import random
import urllib2
from string import letters
from datetime import datetime
from xml.dom import minidom

from google.appengine.ext import db

# Set up our templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

secretKey = "BwWuOrchjptblMWljjbOxzapj"

# Alphabets for our ROT13 algorithm
alphabetLower = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
alphabetUpper = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'] 

# RegEx patterns for usernames, passwords, and emails
usernamePattern = "^[a-zA-Z0-9_-]{3,20}$"
passwordPattern = "^.{3,20}$"
emailPattern = "^[\S]+@[\S]+\.[\S]+$" 

class Handler(webapp2.RequestHandler):
	"""
	Main Handler to inherit from
	"""
	def write(self, *args, **kwargs):
		self.response.out.write(*args, **kwargs)
	
	def render_str(self, template, **params):
		jinjaTemplate = jinja_env.get_template(template)
		return jinjaTemplate.render(params)
	
	def render(self, template, **kwargs):
		self.write(self.render_str(template, **kwargs))

class Art(db.Model):
	"""
	Art db entry for the ascii art page
	"""
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coordinates = db.GeoPtProperty()

class Post(db.Model):
	"""
	Blog Post db entry
	"""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.StringProperty(required = True)
	createdExact = db.DateTimeProperty(auto_now_add = True)

IP_URL = "http://api.hostip.info/?ip="	
def getCords(ip):
	ip = "4.2.2.2"
	ip = "23.24.209.141"
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except:
		return
	
	if content:
		d = minidom.parseString(content)
    	coordinates = d.getElementsByTagName("gml:coordinates")
    	if coordinates and len(coordinates) > 0 and coordinates[0].firstChild.nodeValue:
        	latLong = coordinates[0].firstChild.nodeValue.split(",")
        	return db.GeoPt(latLong[1], latLong[0])
	
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmapsImg(points):
	markers = "&".join("markers={0},{1}".format(p.lat, p.lon) for p in points)
	return GMAPS_URL + markers

class AsciiHandler(Handler):
	"""
	AsciiHandler is for handling our main ascii art page. We display old art
	on the page as well as giving the user a form for making new art.
	If the user submits invalid input, we spit out an error.
	"""
	def render_front(self, title="", art="", error=""):
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC LIMIT 10")
	
		# Don't do the query multiple times! Store in a list
		arts = list(arts)
		
		points = filter(None, (a.coordinates for a in arts))
		imageURL = None
		if points:
			imageURL = gmapsImg(points)
	
		self.render("asciifront.html", title=title, art=art, error=error, arts=arts,
										imageURL = imageURL)
		
	def get(self):
		self.render_front()
		
	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")
		
		if title and art:
			a = Art(title=title, art=art)
			coordinates = getCords(self.request.remote_addr)
			
			if coordinates:
				a.coordinates = coordinates
			a.put()
			
			self.render_front(title, art)
		else:
			error = "Gotta have both title and artwork!"
			self.render_front(title, art, error)

class BlogHandler(Handler):
	"""
	BlogHandler is the standard page for our blog-- both the front page and any
	archives. We offset our query by the page number, if we're in the archives,
	and we show next and back buttons as appropriate!
	"""
	def get(self, pageNo="1"):
		offset = (int(pageNo)-1) * 10
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY createdExact DESC LIMIT 10 OFFSET %d" % offset)
		
		postsLeft = (int(pageNo) - 1) * 10
		postsLeft = posts.count() - postsLeft
		
		backPage = int(pageNo) - 1
		
		if postsLeft > 10:
			nextPage = int(pageNo) + 1
		else:
			nextPage = 0
		
		if self.user:
			button = "logout"
		else:
			button = "login"
		
		
		self.render("blog.html", posts=posts, nextPage=nextPage, backPage=backPage, button=button)
	
	def setCookie(self, name, value):
		cookie = make_secure_val(value)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie))
	
	def readCookie(self, name):
		cookie = self.request.cookies.get(name)
		return cookie and check_secure_val(cookie)
	
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.readCookie('user_id')
		self.user = uid and User.by_id(int(uid))

class BlogJson(BlogHandler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY createdExact DESC LIMIT 10")
		
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		
		jsonList = []
		
		for post in posts:
			jsonList.append({'content' : post.content, 'subject' : post.subject, 
						'created' : post.created})
		self.response.out.write(json.dumps(jsonList))

# for json: Content-type application/json; charset=UTF-8
# list of dictionaries that have content, subject, and created if we can
class PermalinkJson(BlogHandler):
	def get(self, postNum=""):
		if postNum == "":
			self.response.out.write("Not a real post!")
		else:
			postNum = int(postNum)
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		post = Post.get_by_id(int(postNum))		
		jsonList = [{'content' : post.content, 'subject' : post.subject, 
						'created' : post.created}]
		self.response.out.write(json.dumps(jsonList))
	
class NewPostHandler(BlogHandler):
	"""
	NewPostHandler handlers the form for adding a new post to our blog.
	The user must submit a valid subject and valid content for it to be stored
	in our database and displayed on the front blog page. Successful submission
	redirects to a permalink.
	"""
	def render_front(self, subject="", content="", error=""):
		self.render("newPost.html", subject=subject, content=content, error=error)
		
	def get(self):
		if self.user:		
			self.render_front()
		else:
			self.redirect('/blog/login')
		
	def post(self):
		if not self.user:
			self.redirect('/blog')
			
		subject = self.request.get("subject")
		content = self.request.get("content")
		
		if subject and content:
			created = datetime.utcnow().strftime("%I:%M%p %A, %B %d, %Y")
			p = Post(subject=subject, content=content, created=created)
			p.put()
						
			self.redirect("/blog/%d" % p.key().id())
		else:
			error = "Gotta have both a subject and some content!"
			self.render_front(subject, content, error)

class OldPostHandler(BlogHandler):
	"""
	OldPostHandler is our handler for the permalink pages that exist for each old blog post.
	"""
	def get(self, post_id):
		post_id = int(post_id)
		post = Post.get_by_id(int(post_id))
		
		self.render("oldPost.html", post=post)
		
def convertString(input=""):
	"""
	convertString is a handy function for encrypting any string with the easy to 
	crack ROT13 algorithm.
	"""
	output = ""
	for i in range(len(input)):
		char = input[i]
		if char in alphabetLower:
			index = alphabetLower.index(char)
			indexAdjusted = (index + 13) % 26
			output += alphabetLower[indexAdjusted]
		elif char in alphabetUpper:
			index = alphabetUpper.index(char)
			indexAdjusted = (index + 13) % 26
			output += alphabetUpper[indexAdjusted]
		else:
			output += char
	return output


class MainHandler(Handler):
	"""
	Our home page handler!
	"""
	def get(self):
		self.render("mainPage.html")


class Rot13Handler(Handler):
	"""
	Our handler for the ROT13 algorithm page
	"""
	def get(self):
		self.render("rot13.html")
	def post(self):
		input = self.request.get('text')
		output = convertString(input)
		self.render("rot13.html", output=output)
		
class CookieTester(Handler):
	"""
	Testing out settings some cookies
	"""
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		visits = 0
		visit_cookie_str = self.request.cookies.get('visits')
		if visit_cookie_str:
			cookie_val = self.check_secure_val(visit_cookie_str)
			if cookie_val:
				visits = int(cookie_val)
		
		visits += 1
		new_cookie_val = self.make_secure_val(str(visits))
		self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
		self.response.out.write("You've visited this page %s times!" % visits)
		
	def hashIt(self, s):
		return hmac.new(secretKey, s).hexdigest()
		
	def make_secure_val(self, s):
		return "%s|%s" % (s, self.hashIt(s))
		
	def check_secure_val(self, h):
		value = h.split("|")[0]
		if h == self.make_secure_val(value):
			return value
		else:
			return None

class SignupHandler(BlogHandler):
	"""
	A handler for our fake signup page! Soon this will be a part of the blog
	The user has to submit a valid username, a valid password (twice, and they
	have to match), and if the user submits an email (it's optional), it has to 
	be a valid email. It sets a cookie in the user's browser with the username
	"""
	def get(self):
		self.render("signup.html")

	def post(self):
		error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')
		
		parameters = {'username' : self.username, 'email' : self.email}
		
		if not validate_username(self.username):
			error = True
			parameters['error_username'] = "That's not a valid username" 
		if not validate_password(self.password):
			error = True
			parameters['error_password'] = "That's not a valid password"
		elif not validate_passwords(self.password, self.verify):
			error = True
			parameters['error_verify'] = "Passwords don't match" 
		
		if not validate_email(self.email):
			error = True
			parameters['error_email'] = "That's not a valid email"
			
		if error:
			self.render("signup.html", **parameters)
		else:
			self.done()
			
			
	def done(self, *args, **kwargs):
		raise

class Register(SignupHandler):
	def done(self):
		
		self.response.headers['Content-Type'] = 'text/plain'
		
		u = User.get_by_name(self.username)
		
		if u:
			##redirect
			self.render('signup.html', error_username = "That user already exists")
		else:
			u = User.register(username=self.username, password=self.password, email=self.email)
			
			u.put()
			
			self.setCookie('user_id', str(u.key().id()))
			
			self.redirect('/thanks')

class LoginHandler(BlogHandler):
	def get(self):
		if self.user:
			self.redirect('/blog')
		else:
			self.render('login.html')
	
	def post(self):
		error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		
		parameters = {'usernane' : self.username}
		
		if not validate_username(self.username):
			error = True
			parameters['error_username'] = "That's not a valid username" 
		if not validate_password(self.password):
			error = True
			parameters['error_password'] = "That's not a valid password"
		
		if error:
			self.render("login.html", **parameters)
		else:
		
			u = User.login(self.username, self.password)
				
			if u:
				self.response.headers['Content-Type'] = 'text/plain'
				self.setCookie('user_id', str(u.key().id()))
				
				self.redirect('/welcome')
			else:
				parameters['login_error'] = "Invalid login"
				self.render("login.html", **parameters)

class LogoutHandler(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/blog/signup')
	
def validate_username(username):
	"""
	validating the username for our fake signup.
	"""
	if username:
		prog = re.compile(usernamePattern)
		match = prog.match(username)
		if match:
			return True
	
def validate_password(password):
	"""
	validating the password for our fake signup.
	"""
	if password:
		prog = re.compile(passwordPattern)
		match = prog.match(password)
		if match:
			return True

def validate_passwords(password, verify):
	"""
	validating that our passwords match.
	"""
	if password == verify:
		return True

def validate_email(email):
	"""
	validating the email for our fake signup
	"""
	if email and email != "":
		prog = re.compile(emailPattern)
		match  = prog.match(email)
		if match:
			return True	
	else:
		return True


class User(db.Model):
	"""
	User db entry for storing username and password
	"""
	username = db.StringProperty(required = True)
	hashedPassword = db.StringProperty(required = True)
	signupDate = db.DateTimeProperty(auto_now_add = True)
	email = db.StringProperty()
	
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)
	
	@classmethod
	def get_by_name(cls, username):
		return User.all().filter('username =', username).get()
	
	@classmethod
	def register(cls, username, password, email = None):
		hashedPassword = makePasswordHash(username, password)
		return User(username = username, hashedPassword = hashedPassword, email = email)
	
	@classmethod
	def login(cls, username, password):
		user = cls.get_by_name(username)
		if user and validatePassword(username, password, user.hashedPassword):
			return user
		
def hashIt(s):
	return hmac.new(secretKey, s).hexdigest()
	
def make_secure_val(s):
	return "%s|%s" % (s, hashIt(s))
	
def check_secure_val(h):
	value = h.split("|")[0]
	if h == make_secure_val(value):
		return value
	else:
		return None

def makeSalt(length = 5):
	return "".join(random.choice(letters) for x in range(length))
	
def makePasswordHash(name, pwd, salt=None):
	if not salt:
		salt = makeSalt()
	h = hashlib.sha256(name + pwd + salt).hexdigest()
	return '%s,%s' % (salt, h)

def validatePassword(name, password, h):
	salt = h.split(",")[0]
	return h == makePasswordHash(name, password, salt)
	
class ThanksHandler(BlogHandler):
	"""
	A simple handler for when the user signs up for the page
	"""
	def get(self):
		if self.user:
			self.messageForUser()
		else:
			self.redirect('/blog/signup')
	
	def messageForUser(self):
		self.response.out.write("<h1>thanks, %s!</h1><br><a href=\"blog\">\
			Back to the blog</a>" % self.user.username)

class WelcomeHandler(ThanksHandler):
	"""
	A handler for welcoming in old users
	"""
	def messageForUser(self):
		self.response.out.write("<h1>Welcome back, %s!</h1><br><a href=\"blog\">\
			Back to the blog</a>" % self.user.username)

class CraigsListHandler(Handler):
	def get(self):
		p = urllib2.urlopen("http://www.craigslist.com")
		#craigsListXML = p.read()
		#d = minidom.parseString(craigsListXML)
		#apartments = d.getElementsByTagName("item")
		#latestApartment = apartments[0]
		#title = latestApartment.getElementsByTagName('title')[0].firstChild.wholeText
		#url = latestApartments.getElementsByTagName('link')[0].firstChild.wholeText
		
		#self.response.out.write("<h1>{0}<br><br>{1}".format(title, url))
		self.response.out.write("craigslist it")
# Make the app go!
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/unit2/rot13', Rot13Handler), ('/thanks', ThanksHandler), \
    		('/blog/signup', Register), ('/unit3/ascii', AsciiHandler), \
    		('/blog', BlogHandler), ('/blog/newpost', NewPostHandler), \
    		(r'/blog/(\d+)', OldPostHandler), (r'/blog/page(\d+)', BlogHandler), \
    		(r'/cookies', CookieTester), (r'/blog/login', LoginHandler), \
    		(r'/welcome', WelcomeHandler), (r'/blog/logout', LogoutHandler), \
    		(r'/craigslist', CraigsListHandler), (r'/blog/(\d+).json', PermalinkJson), \
    		(r'/blog/.json', BlogJson)], debug=True)
