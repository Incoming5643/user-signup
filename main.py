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

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
	return USER_RE.match(username)
	
def valid_password(password):
	return PASSWORD_RE.match(password)
	
def valid_email(email):
	if(not email):
		return True
	return EMAIL_RE.match(email)
	
def build_page(username = "", email = "", username_warning = False, password_warning = False, password_match_warning = False, email_warning = False):
	header = "<h1>User Signup</h1>"
	username_warning_message = ""
	if(username_warning):
		username_warning_message = " <b>This is an invalid user name.</b>"
	password_warning_message = ""
	if(password_warning):
		password_warning_message = " <b>That was an invalid password.</b>"
	password_match_warning_message = ""
	if(password_match_warning):
		password_match_warning_message = " <b>Your passwords did not match.</b>"
	email_warning_message = ""
	if(email_warning):
		email_warning_message = " <b>This is an invalid email address.</color></b>"
	user_input = "<label>Username</label><br /><input type='text'  name = 'username' value = '" + username + "'></input>" + username_warning_message
	pass_input = "<br /><br /><label>Password</label><br /><input type='password'  name = 'password'></input>" + password_warning_message
	verify_input = "<br /><br /><label>Verify Password</label><br /><input type='password'  name = 'verify'></input>"  + password_match_warning_message
	email_input = "<br /><br /><label>E-mail (optional)</label><br /><input type='text'  name = 'email' value ='" + email +"'></input>" + email_warning_message
	form = header + "<form method = 'post'>" + user_input + pass_input + verify_input + email_input + "<br /><br /><input type = 'submit'/></form>"
	return(form)

class MainHandler(webapp2.RequestHandler):
	def get(self):
		self.response.write(build_page())
		
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		
		if(valid_username(username) and valid_password(password) and password == verify and valid_email(email)):
			self.redirect("/welcome?username="+username)
		else:
			self.response.write(build_page(username,email, not valid_username(username), not valid_password(password), not password == verify, not valid_email(email)))

class Welcome(webapp2.RequestHandler):
	def get(self):
		username = self.request.get("username")
		self.response.write("<h1>Welcome, " + username + "!</h1>")
		
app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/welcome', Welcome)
], debug=True)
