#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import zyz_debug
import markdown
import os.path
import re
import hashlib
import tornado.autoreload
import tornado.auth
import tornado.database
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata
from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1:3306", help="blog database host")
define("mysql_database", default="blog", help="blog database name")
define("mysql_user", default="root", help="blog database user")
define("mysql_password", default="firezyz", help="blog database password")

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/archive", ArchiveHandler),
            (r"/feed", FeedHandler),
            (r"/entry/([^/]+)", EntryHandler),
            (r"/compose", ComposeHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/admin", AdminHandler),
            (r"/auth/register", AuthRegisterHandler),
        ]
        settings = dict(
            blog_title=u"Firezyz's Blog",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Entry": EntryModule,"AdminUser": AdminUserModule,"AdminEntry":AdminEntryModule},
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            autoescape=None,
            debug = True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        # Have one global connection to the blog DB across all handlers
        self.db = tornado.database.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db
    def get_current_user(self):
        #print "get_current_user"
        user_id = self.get_secure_cookie("user")
        #print user_id
        if not user_id: return None
        return self.db.get("SELECT * FROM users WHERE id = %s", int(user_id))
class HomeHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 5")
        if not entries:
            self.redirect("/compose")
            return
        for entry in entries:
            if len(entry['html'])>500:
                entry['htmls'] = entry['html'][:490]
            else:
                entry['htmls'] = ''
        #print entries
        self.render("home.html", entries=entries)
class EntryHandler(BaseHandler):
    def get(self, slug):
        entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
        if not entry: raise tornado.web.HTTPError(404)
        entry['htmls'] = ''
        self.render("entry.html", entry=entry)
class ArchiveHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC")
        self.render("archive.html", entries=entries)
class FeedHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 10")
        self.set_header("Content-Type", "application/atom+xml")
        self.render("feed.xml", entries=entries)
class ComposeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        id = self.get_argument("id", None)
        entry = None
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
        self.render("compose.html", entry=entry)
    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id", None)
        title = self.get_argument("title")
        text = self.get_argument("markdown")
        tag = self.get_argument("tag","")
        html = markdown.markdown(text)
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
            if not entry: raise tornado.web.HTTPError(404)
            slug = entry.slug
            self.db.execute(
                "UPDATE entries SET title = %s, markdown = %s, html = %s "
                "WHERE id = %s", title, text, html, int(id))
        else:
            slug = unicodedata.normalize("NFKD", title).encode(
                "ascii", "ignore")
            slug = re.sub(r"[^\w]+", " ", slug)
            slug = "-".join(slug.lower().strip().split())
            if not slug: slug = "entry"
            while True:
                e = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
                if not e: break
                slug += "-2"
            self.db.execute(
                "INSERT INTO entries (author_id,title,slug,tag,markdown,html,"
                "published) VALUES (%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP())",
                self.current_user.id, title, slug, tag, text, html)
        self.redirect("/entry/" + slug)
class AuthLoginHandler(BaseHandler):
    def get(self):
        self.render("login.html")
    def post(self):
        email = self.get_argument("email", None) 
        pwd = self.get_argument("password",None)
        if email and pwd:
            md5 = hashlib.md5()
            md5.update(pwd)
            password = md5.hexdigest()
            user_id = self._auth_(email,password)
            self.set_secure_cookie("user", user_id,expires_days=None)
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html")
        #self.authenticate_redirect()
    def _auth_(self,email,password):
        users = self.db.get("SELECT * FROM users WHERE email = %s AND password = %s",email,password)
       # if len(users) == 0:
       #     user_id = self.db.execute(
       #         "INSERT INTO users (username,password) VALUES (%s,%s)",username,password)
        if users:
            user_id = users["id"]
        else:
            self.redirect("/")
        return str(user_id)
class CommonTools():
    def user_auth(self,username,password):
        users = self.db.get("SELECT * FROM users WHERE username = %s AND password = %s",username,password)
       # if len(users) == 0:
       #     user_id = self.db.execute(
       #         "INSERT INTO users (username,password) VALUES (%s,%s)",username,password)
        if users:
            user_id = users["id"]
        else:
            self.redirect("/")
            return
        return str(user_id)
    def user_level(self,user_id):
        user = self.db.get("SELECT * FROM users WHERE user_id = %s",user_id)
        if user['username'] == 'firezyz':
            return True
        return False
class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))
class AdminHandler(BaseHandler):
    def get(self):
        self._auth_()
        users = self.db.query("SELECT * FROM users")
        entries = self.db.query("SELECT * from entries")
        #print users
        #print entries
        self.render("admin.html",entries = entries,users = users)

    def _delete_(self, opObj,opObjId):
        if opObj in ['user']:
            self._delete_user_(opObjId)
        elif opObj in ['entry']:
            self._delete_entry_(opObjId)
    def _delete_user_(self,opObjId):
        #print opObjId
        self.db.execute("DELETE FROM users WHERE id = %s",opObjId)
    def _delete_entry_(self,opObjId):
        self.db.execute("DELETE FROM entries WHERE id = %s",opObjId)
    def _auth_(self):
        user_id = self.get_secure_cookie("user")
        user = self.db.get("SELECT * FROM users WHERE id = %s",user_id)
        if not user:
            self.clear_cookie("user")
            self.redirect("/")

class AuthRegisterHandler(BaseHandler):
    def get(self):
        self.render('register.html')
    def post(self):
        email = self.get_argument("email")
        pwd = self.get_argument("password")
        username = self.get_argument('username') if self.get_argument('username') else email
        print email
        print pwd
        print username
        if not (email and pwd):
            self.redirect("/auth/register")
        md5 = hashlib.md5()
        md5.update(pwd)
        password = md5.hexdigest()
        print password
        user = self.db.get('SELECT * FROM users WHERE email = %s AND password = %s',email,password)
        if user:
            self.redirect("/auth/register")
        user_id = self.db.execute("INSERT INTO users (username,email,password) VALUES(%s,%s,%s)",username,email,password)
        if not user_id:
            self.redirect("/auth/register")
        print user_id
        self.set_secure_cookie("user", str(user_id) ,expires_days=None)
        self.redirect(self.get_argument("next", "/"))

class EntryModule(tornado.web.UIModule):
    def render(self, entry):
        return self.render_string("modules/entry.html", entry=entry)
class AdminEntryModule(tornado.web.UIModule):
    def render(self,entries):
        return self.render_string("modules/admin/entry.html",entries = entries)
class AdminUserModule(tornado.web.UIModule):
    def render(self, users):
        return self.render_string("modules/admin/user.html",users = users)
def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
if __name__ == "__main__":
    main()
