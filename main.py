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
import hashlib
import hmac
import random
from string import letters
from datetime import datetime

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

class Post(db.Model):
	"""
	Blog Post db entry
	"""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.StringProperty(required = True)
	createdExact = db.DateTimeProperty(auto_now_add = True)
	
class AsciiHandler(Handler):
	"""
	AsciiHandler is for handling our main ascii art page. We display old art
	on the page as well as giving the user a form for making new art.
	If the user submits invalid input, we spit out an error.
	"""
	def render_front(self, title="", art="", error=""):
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC ")
	
		self.render("asciifront.html", title=title, art=art, error=error, arts=arts)
		
	def get(self):
		self.render_front()
		
	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")
		
		if title and art:
			a = Art(title=title, art=art)
			a.put()
			
			self.render_front(title, art)
		else:
			error = "Gotta have both title and artwork!"
			self.render_front(title, art, error)
		
class NewPostHandler(Handler):
	"""
	NewPostHandler handlers the form for adding a new post to our blog.
	The user must submit a valid subject and valid content for it to be stored
	in our database and displayed on the front blog page. Successful submission
	redirects to a permalink.
	"""
	def render_front(self, subject="", content="", error=""):
		self.render("newPost.html", subject=subject, content=content, error=error)
		
	def get(self):		
		self.render_front()
		
	def post(self):
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
			self.render("blog.html", posts=posts, nextPage=int(pageNo)+1, backPage=backPage)
		else:
			self.render("blog.html", posts=posts, nextPage="", backPage=backPage)
	
class OldPostHandler(Handler):
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

class SignupHandler(Handler):
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
			
			self.login(u)
		
		# name_cookie_str = self.request.cookies.get('name')
# 		if name_cookie_str:
# 			cookie_val = self.check_secure_val(name_cookie_str)
# 			if cookie_val:
# 				name = cookie_val
# 			else:
# 				self.render("signup.html", **parameters)
# 				return
# 		else:
# 			name = username
# 		
# 		new_cookie_val = self.make_secure_val(str(name))
# 		self.SetCookie("name", new_cookie_val)
			self.redirect('/thanks')
	
	def setCookie(self, name, value):
		cookie = make_secure_val(value)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie))
	
	def readCookie(self, name):
		cookie = self.request.cookies.get(name)
		return cookie and check_secure_val(cookie)
	
	def login(self, user):
		self.setCookie('user_id', str(user.key().id()))

class LoginHandler(Handler):
	def get(self):
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
			self.render("signup.html", **parameters)
		else:
			self.redirect('/welcome')
	
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
	
class ThanksHandler(Handler):
	"""
	A simple handler for when the user submits valid data on our fake signup page
	"""
	def get(self):
		user_ID_cookie = self.request.cookies.get('user_id')
		if user_ID_cookie and check_secure_val(user_ID_cookie):
			uid = user_ID_cookie.split("|")[0]
			user = User.by_id(int(uid))
			self.response.out.write("<h1>thanks, %s!</h1>" % user.username)
		else:
			self.redirect('/signup')

# Make the app go!
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/unit2/rot13', Rot13Handler), ('/thanks', ThanksHandler), \
    		('/signup', Register), ('/unit3/ascii', AsciiHandler), \
    		('/blog', BlogHandler), ('/blog/newpost', NewPostHandler), \
    		(r'/blog/(\d+)', OldPostHandler), (r'/blog/page(\d+)', BlogHandler), \
    		(r'/cookies', CookieTester), (r'/login', LoginHandler)], debug=True)
