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
import sys
import jinja2
from datetime import date

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

alphabetLower = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
alphabetUpper = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'] 

POST_NUMBER = 1

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

class BlogHandler(Handler):
	def get(self):
		
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY createdExact DESC LIMIT 10")
		
		self.render("blog.html", posts=posts, nextPage=2)
		
class NewPostHandler(Handler):
	def render_front(self, subject="", content="", error=""):
		self.render("newPost.html", subject=subject, content=content, error=error)
		
	def get(self):		
		self.render_front()
		
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		
		if subject and content:
			created = str(date.today())
			p = Post(subject=subject, content=content, created=created)
			p.put()
						
			self.redirect("/blog/%d" % p.key().id())
		else:
			error = "Gotta have both a subject and some content!"
			self.render_front(subject, content, error)

class BlogOldPageHandler(Handler):
	def get(self, pageNo):
		offset = (int(pageNo)-1) * 10
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY createdExact DESC LIMIT 10 OFFSET %d" % offset)
		if posts:
			self.render("blog.html", posts=posts, nextPage=int(pageNo)+1)
		else:
			print "none for you"

class OldPostHandler(Handler):
	def get(self, post_id):
		post_id = int(post_id)
		post = Post.get_by_id(int(post_id))
		
		self.render("oldPost.html", post=post)
		
def convertString(input=""):	
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
	def get(self):
		self.render("mainPage.html")


class Rot13Handler(Handler):
    	def get(self):
        	self.render("rot13.html")

    	def post(self):
        	input = self.request.get('text')
        	output = convertString(input)
        	self.render("rot13.html", output=output)

class SignupHandler(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		
		parameters = {'username' : username, 'email' : email}
		
		if not self.validate_username(username):
			error = True
			parameters['error_username'] = "That's not a valid username" 
		if not self.validate_password(password):
			error = True
			parameters['error_password'] = "That's not a valid password"
		elif not self.validate_passwords(password, verify):
			error = True
			parameters['error_verify'] = "Passwords don't match" 
		
		if not self.validate_email(email):
			error = True
			parameters['error_email'] = "That's not a valid email"
			
		if error:
			self.render("signup.html", **parameters)
		else:
			self.redirect('/thanks?username=' + username)

	def validate_username(self, username):
		if username:
			prog = re.compile(usernamePattern)
			match = prog.match(username)
			if match:
				return True
	
	def validate_password(self, password):
		if password:
			prog = re.compile(passwordPattern)
			match = prog.match(password)
			if match:
				return True
	
	def validate_passwords(self, password, verify):
		if password == verify:
			return True

	def validate_email(self, email):
		if email and email != "":
			prog = re.compile(emailPattern)
			match  = prog.match(email)
			if match:
				return True	
		else:
			return True

class ThanksHandler(Handler):
	def get(self):
		username = self.request.get('username')
		self.response.out.write("<h1>thanks, %s!</h1>" % username)

app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/unit2/rot13', Rot13Handler), ('/thanks', ThanksHandler), \
    		('/unit2/signup', SignupHandler), ('/unit3/ascii', AsciiHandler), \
    		('/blog', BlogHandler), ('/blog/newpost', NewPostHandler), \
    		(r'/blog/(\d+)', OldPostHandler), (r'/blog/page(\d+)', BlogOldPageHandler)], debug=True)
