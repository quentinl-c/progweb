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
import os
import jinja2
import webapp2
import hashlib
import re

from google.appengine.ext import db

'''
templates initialisation
'''
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape=True)

'''
define hash functions
'''

SECRET = "immoScret"

def make_secure_val(s):
	return "%s|%s" % (s, hashlib.md5(s).hexdigest())

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def hash_str(s):
		return hmac.new(SECRET, s).hexdigest()

'''
vrifications for login and password
'''

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
	return USER_RE.match(username)

def valid_password(password):
	return PASS_RE.match(password)

def valid_verify(password, verify):
	return password==verify

def valid_email(email):
	return EMAIL_RE.match(email)

'''
Database management
'''
#nothing...

'''
web app
'''

class Handler(webapp2.RequestHandler):
	def write(self, *a,**kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template,**kw):
		self.write(self.render_str(template,**kw))

class MainHandler(Handler):

	'''
	Simple redirection to the signup form
	'''
	def get(self):
		self.redirect('/blog/signup')

class Signup(Handler):

	'''
	Signup web page handler which save the user informations in a cookie wether the is properly filled
	'''
	def get(self):

		self.render("signup.html", er_user = "", er_pass ="", er_verif="", er_email="")

	def post(self):

		#Save value passed by post method
		content = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		#Check wheter the content repect the conditions
		v_user = valid_username(content)
		v_pass = valid_password(password)
		v_verif = valid_verify(password,verify)
		v_email = valid_email(email)

		#Save the cookie value (if already exists)
		user_cookie_str = self.request.cookies.get('user_id')


		params ={}
		if content:
			params['user']=content

		if content and email:
			params['email']=email

		##### Check the form #####
		invalid_form = False

		#Check the username
		already_used = False

		if user_cookie_str :
			cookie_val = check_secure_val(user_cookie_str)
			if cookie_val == content :
				already_used = True
				v_user = False

		if v_user:
			params['er_user'] = ""
		elif already_used:
			params ['er_user'] = "This login is already used"
			invalid_form = True
		else :
			params['er_user'] = "That's not a valid username"
			invalid_form = True


		#Check the password
		if v_pass:
			params['er_pass'] = ""
		else:
			params['er_pass'] = "That's not a valid password"
			invalid_form = True
		if v_verif:
			params['er_email'] = ""
		else :
			params['er_email']="The second password is not correct"
			invalid_form = True

		#Check the email address
		if v_email:
			params['er_verif'] = ""
		else:
			params['er_verif'] = "Passwords didn't match"
			invalid_form = True

		#### Make the right redirection ####
		if not invalid_form :
			self.redirect("/blog/welcome")
			new_cookie_val = make_secure_val(params['user'])
			self.response.headers.add_header('Set-Cookie', 'user_id = %s; Path=/' %str(new_cookie_val))
		else:
			self.render("signup.html", **params)

class Welcome(Handler):
	'''
	Handler for the welcome page which display the username whether the cookie is valid
	'''

	def get(self):

		#Check the cokie validity 
		username_cookie = self.request.cookies.get('user_id')

		if username_cookie:
			cookie_val = check_secure_val(username_cookie)
			if cookie_val :
				self.render("welcome.html", username = cookie_val)
			else :
				self.redirect("/blog/signup")
		else:
			self.redirect("/blog/signup")


app = webapp2.WSGIApplication([
	('/blog', MainHandler),
	('/blog/signup', Signup),
	('/blog/welcome', Welcome)
], debug=True)
