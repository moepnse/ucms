#!/opt/python2.7/bin/python
# -*- coding: utf-8 -*-

__author__ = 'Richard Lamboj'
__copyright__ = 'Copyright 2016, Unicom'
__credits__ = ['Richard Lamboj']
__license__ = 'Proprietary'
__version__ = '0.1'
__maintainer__ = 'Richard Lamboj'
__email__ = 'rlamboj@unicom.ws'
__status__ = 'Development'


# standard library imports
import os
import re
import sys
import math
import time
import datetime
import hashlib
import binascii
import ConfigParser
from functools import wraps

# related third party imports
#import PIL.Image
import cherrypy
import MySQLdb

# local application/library specific imports


"""
[db]
host=10.0.19.61
name=mailserver
user=mailuser
passwd=Pa$sw0rd
"""

config = ConfigParser.ConfigParser({'port': '3306'})
config.read('configuration.ini')

db_host = config.get('db', 'host')
db_port = config.get('db', 'port')
db_name = config.get('db', 'name')
db_user = config.get('db', 'user')
db_passwd = config.get('db', 'passwd')


def connect(thread_index): 
    # Create a connection and store it in the current thread 
    cherrypy.thread_data.db = DB(db_host, db_port, db_user, db_pass, db_name)


# Tell CherryPy to call "connect" for each thread, when it starts up 
cherrypy.engine.subscribe('start_thread', connect)


#def authorize(admin=False, debug=False):
#    if 'username' not in cherrypy.session or (admin and not cherrypy.session.get('is_admin', False)):
#        raise cherrypy.HTTPRedirect("/")


#cherrypy.tools.authorize = cherrypy.Tool("before_handler", authorize, priority=59)


def authorize(admin=False, admin_or_owner=False):
    def __decorator(func):
        @wraps(func)
        def __wrapper(*args, **kwargs):
            if 'username' not in cherrypy.session or ((admin and not cherrypy.session.get('is_admin', False)) or (admin_or_owner and (args[1] != cherrypy.session['username'] and not cherrypy.session.get('is_admin', False)))):
                raise cherrypy.HTTPRedirect("/")
            return func(*args, **kwargs)
        return __wrapper
    return __decorator


class DB:

    def __init__(self, host, port, username, password, db_name):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._db_name = db_name

    def connect(self):
        self._connection = MySQLdb.connect(
            host = self._host,
            port = self._port,
            db = self._db_name,
            user = self._username, passwd = self._password,
            use_unicode=True, charset="utf8"
        )
        self._connection.ping(True)
        self._cursor = self._connection.cursor()
        self._d_cursor = self._connection.cursor(MySQLdb.cursors.DictCursor)

    def _sql_execute(self, sql, values=None, as_dict=False):
        if as_dict:
            self._d_cursor.execute(sql, values)
            return self._d_cursor
        else:
            self._cursor.execute(sql, values)
            return self._cursor

    def sql_execute(self, sql, values=None, as_dict=False):
        try:
            return self._sql_execute(sql, values, as_dict)
        except (AttributeError, MySQLdb.OperationalError):
            self.connect()
            return self._sql_execute(sql, values, as_dict)

    def commit(self):
        self._connection.commit()


class UCMS:

    __template_index = u"""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <title>UCMS</title>
        <meta name="keywords" content="ucms">
        <meta name="robots" content="index, follow" />
        <meta name="author" content="Richard Lamboj" />
        <!-- HTML 4.x -->
        <meta http-equiv="content-type" content="text/html; charset=utf-8">
        <!-- HTML5 -->
        <meta charset="utf-8">
        <link rel="stylesheet" type="text/css" href="/static/style.css">
    </head>
    <body>
        %(html)s
    </body>
</html>
    """

    __template_logged_in = u"""
        %(menu)s <div id="content"><div id="top_menu">%(top_menu)s</div>%(html)s</div>
    """

    __template_customer_menu_entrys = u"""
        <a href="/users/" target="">Users</a>
        <a href="/domains/" target="">Domains</a>"""

    __template_customer_menu_entrys__admin_view = u"""
        <a href="/customer/%(customer)s/users/" target="">Users</a>
        <a href="/customer/%(customer)s/domains/" target="">Domains</a>"""

    __template_menu = u"""
    <div id="menu">
        <img id="logo" src="/static/imgs/unicom_wachslogo.png">
        %(menu_entrys)s
        <a href="/logout/" target="">Logout</a>
    </div>
    """

    __template_admin_menu_entrys = u"""
        <a href="/customers/" target="">Customers</a>
    """

    __template_login = u"""
        <div id="login">
            <div>
                <form action="%(target)s" method="POST">
                    <h1>Login</h1>
                    <div>
                        <label>Username</label>
                        <input type="text" name="username" class="%(username_class)s" value="">
                    </div>
                    <div>
                        <label>Passwort</label>
                        <input type="password" name="password" class="%(password_class)s" value="">
                    </div>
                    <input type="submit" value="login">
                </form>
            </div>
        </div>
    """

    __template_add_customer= u"""
            <div>
                <form action="%(target)s" method="POST">
                    <h1>Add Customer</h1>
                    <div>
                        <label>Username</label>
                        <input type="text" name="username" class="%(username_class)s" value="">
                    </div>
                    <div>
                        <div>
                            <label>Passwort</label>
                            <input type="password" name="password" class="%(password_class)s" value="">
                        </div>
                        <div>
                            <label>Passwort</label>
                            <input type="password" name="password2" class="%(password_class)s" value="">
                        </div>
                    </div>
                    <div>
                        <label>E-Mail</label>
                        <input type="text" name="email" class="%(email_class)s" value="">
                    </div>
                    <input type="submit" value="Add">
                </form>
            </div>
    """

    __template_customer_add_virtual_user_form= u"""
            <div>
                <form action="/customer/%(username)s/add/user/" method="POST">
                    <h1>Add Virtual User</h1>
                    <div>
                        <input type="hidden" name="domain" value="%(name)s">
                        <div>
                            <label>User</label>
                            <input type="text" name="user" class="%(username_class)s" value="">@%(name)s
                        </div>
                        <div>
                            <div>
                                <label>Password</label>
                                <input type="password" name="password" class="%(password_class)s" value="">
                            </div>
                            <div>
                                <label>Password</label>
                                <input type="password" name="password2" class="%(password_class)s" value="">
                            </div>
                        </div>
                    </div>
                    <input type="submit" value="Add">
                </form>
            </div>
    """

    __template_virtual_user_change_pw_form= u"""
            <div>
                <form action="/customer/%(username)s/user/%(name)s/change/pw/" method="POST">
                    <h1>Change Virtual User Password</h1>
                    <div>
                        <div>
                            <label>Password</label>
                            <input type="password" name="password" class="%(password_class)s" value="">
                        </div>
                        <div>
                            <label>Password</label>
                            <input type="password" name="password2" class="%(password_class)s" value="">
                        </div>
                    </div>
                    <input type="submit" value="Change">
                </form>
            </div>
    """

    __template_customer_add_domain_form= u"""
            <div>
                <form action="/customer/%(username)s/add/domain/" method="POST">
                    <h1>Add Domain</h1>
                    <div>
                        <label>Domain</label>
                        <input type="text" name="domain" class="%(domain_class)s" value="">
                    </div>
                    <input type="submit" value="Add">
                </form>
            </div>
    """

    __template_delete_form= u"""
            <div>
                <form action="%(target)s" method="POST">
                    <h1>%(text)s</h1>
                    <input type="submit" name="yes" value="Yes">
                    <input type="submit" name="no" value="No">
                </form>
            </div>
    """

    __template_customer_add_virtual_alias_form= u"""
            <div>
                <form action="/customer/%(username)s/add/alias/" method="POST">
                    <h1>Add Alias</h1>
                    <div>
                        <input type="hidden" name="email" value="%(email)s">
                        <input type="hidden" name="domain" value="%(domain)s">
                        <div>
                            <label>Destination</label>
                            <input type="text" name="destination" class="%(destination_class)s" value="">
                        </div>
                    </div>
                    <input type="submit" value="Add">
                </form>
            </div>
    """

    __template_customer_change_pw_form= u"""
            <div>
                <form action="/customer/%(username)s/change/pw/" method="POST">
                    <h1>Change Customer Password</h1>
                    <div>
                        <div>
                            <label>Passwort</label>
                            <input type="password" name="password" class="%(password_class)s" value="">
                        </div>
                        <div>
                            <label>Passwort</label>
                            <input type="password" name="password2" class="%(password_class)s" value="">
                        </div>
                    </div>
                    <input type="submit" value="Change">
                </form>
            </div>
    """

    __template_customer_change_mail_form= u"""
            <div>
                <form action="/customer/%(username)s/change/email/" method="POST">
                    <h1>Change Customer Mail</h1>
                    <div>
                        <label>E-Mail</label>
                        <input type="text" name="email" class="%(email_class)s" value="%(email)s">
                    </div>
                    <input type="submit" value="Change">
                </form>
            </div>
    """

    __template_customers_table_entry = u"""
        <tr>
            <td><a href="/customer/%(username)s">%(username)s</a></td>
            <td><a href="mailto: %(email)s">%(email)s</a></td>
            <td><a href="/customer/%(username)s/delete">Delete</a></td>
        </tr>
    """

    __template_customers_table = u"""
        <table>
            <thead>
                <tr>
                    <th>
                        Customer
                    </th>
                    <th>
                        E-Mail
                    </th>
                    <th>
                        Action
                    </th>
                </tr>
            </thead>
            <tbody>
                %(tbody)s
            </tbody>
    """

    __template_virtual_domains_table_entry = u"""
        <tr>
            <td>%(id)s</td>
            <td><a href="/customer/%(customer)s/domain/%(name)s">%(name)s</a></td>
            <td><a href="/customer/%(customer)s/domain/%(name)s/delete">Delete</a></td>
        </tr>
    """

    __template_virtual_domains_table = u"""
        <table>
            <thead>
                <tr>
                    <th>
                        id
                    </th>
                    <th>
                        Domain
                    </th>
                    <th>
                        Action
                    </th>
                </tr>
            </thead>
            <tbody>
                %(tbody)s
            </tbody>
    """

    __template_virtual_users_table_entry = u"""
        <tr>
            <td>%(id)s</td>
            <td><a href="/customer/%(customer)s/domain/%(domain)s/%(email)s">%(email)s</a></td>
            <td><a href="/customer/%(customer)s/domain/%(domain)s/%(email)s/delete">Delete</a></td>
        </tr>
    """

    __template_virtual_users_table = u"""
        <table>
            <thead>
                <tr>
                    <th>
                        id
                    </th>
                    <th>
                        E-Mail
                    </th>
                    <th>
                        Action
                    </th>
                </tr>
            </thead>
            <tbody>
                %(tbody)s
            </tbody>
    """

    __template_virtual_aliases_table_entry = u"""
        <tr>
            <td>%(id)s</td>
            <td><a href="/customer/%(customer)s/domain/%(domain)s/%(source)s">%(destination)s</a></td>
            <td><a href="/customer/%(customer)s/domain/%(domain)s/%(source)s/%(destination)s/delete">Delete</a></td>
        </tr>
    """

    __template_virtual_aliases_table = u"""
        <table>
            <thead>
                <tr>
                    <th>
                        id
                    </th>
                    <th>
                        Destination
                    </th>
                    <th>
                        Action
                    </th>
                </tr>
            </thead>
            <tbody>
                %(tbody)s
            </tbody>
    """

    def _add_customer(self, customer, password, email=''):
        c = cherrypy.thread_data.db.sql_execute("""INSERT INTO `customers`
            (`username`, `password`, `email`)
        VALUES
            (%s, ENCRYPT(%s, CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), %s)""", (customer, password, email)
        )
        cherrypy.thread_data.db.commit()

    def _auth_customer(self, customer, password):
        c = cherrypy.thread_data.db.sql_execute("""SELECT 1 FROM `customers` WHERE username = %s AND password = ENCRYPT(%s, `password`)""" ,(customer, password)
        )
        return c.fetchone() is not None

    def _auth_admin(self, admin, password):
        c = cherrypy.thread_data.db.sql_execute("""SELECT 1 FROM `admins` WHERE username = %s AND password = ENCRYPT(%s, `password`)""" ,(admin, password)
        )
        return c.fetchone() is not None

    def _add_admin(self, admin, password, email=''):
        c = cherrypy.thread_data.db.sql_execute("""INSERT INTO `admin`
            (`username`, `password`, `email`)
        VALUES
            (%s, ENCRYPT(%s, CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), %s)""", (admin, password, email)
        )
        cherrypy.thread_data.db.commit()

    def _update_customer(self, **kwargs):
        print """UPDATE customers SET email=%(email)s WHERE username=%(username)s""" % kwargs
        c = cherrypy.thread_data.db.sql_execute("""UPDATE customers SET email=%(email)s WHERE username=%(username)s""", kwargs)
        cherrypy.thread_data.db.commit()

    def _update_customer_password(self, **kwargs):
        c = cherrypy.thread_data.db.sql_execute("""UPDATE customers SET password=ENCRYPT(%(password)s, CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))) WHERE username=%(username)s""", kwargs)
        cherrypy.thread_data.db.commit()

    def _get_customers(self):
        c = cherrypy.thread_data.db.sql_execute("""SELECT id, username, email FROM `customers`""" , None, as_dict=True)
        return c

    def _get_customer(self, username):
        c = cherrypy.thread_data.db.sql_execute("""SELECT id, username, email FROM `customers` WHERE username = %s""" , (username,) , as_dict=True)
        return c.fetchone()

    def _get_virtual_domains(self, username):
        c = cherrypy.thread_data.db.sql_execute("""SELECT vdid AS id, virtual_domains.name FROM `customers_virtual_domains` 
        LEFT JOIN virtual_domains ON customers_virtual_domains.vdid = virtual_domains.id
        LEFT JOIN customers ON customers_virtual_domains.cid = customers.id
        WHERE customers.username = %s""" , (username,),
        as_dict=True)
        return c

    def _get_virtual_domain(self, domain):
        c = cherrypy.thread_data.db.sql_execute("""SELECT vdid AS id, virtual_domains.name FROM `customers_virtual_domains` 
        LEFT JOIN virtual_domains ON customers_virtual_domains.vdid = virtual_domains.id
        LEFT JOIN customers ON customers_virtual_domains.cid = customers.id
        WHERE virtual_domains.name = %s""" , (domain,),
        as_dict=True)
        return c.fetchone()

    def _get_virtual_users(self, vdid):
        c = cherrypy.thread_data.db.sql_execute("""SELECT id, email FROM virtual_users WHERE  domain_id = %s""", (vdid,), as_dict=True)
        return c

    def _get_virtual_user(self, email):
        c = cherrypy.thread_data.db.sql_execute("""SELECT id, email FROM virtual_users WHERE email = %s""", (email,), as_dict=True)
        return c.fetchone()

    def _get_virtual_aliases(self, email):
        c = cherrypy.thread_data.db.sql_execute("""SELECT virtual_aliases.id AS id, destination, email AS source FROM virtual_aliases 
        LEFT JOIN virtual_users ON virtual_aliases.vuid = virtual_users.id 
        WHERE virtual_users.email = %s""", (email,), as_dict=True)
        return c

    def _add_virtual_domain(self, **kwargs):
        c = cherrypy.thread_data.db.sql_execute("""INSERT INTO `virtual_domains`
            (`name`)
        VALUES
            (%(domain)s)""", kwargs
        )
        c = cherrypy.thread_data.db.sql_execute("""SELECT LAST_INSERT_ID();""")
        row = c.fetchone()
        kwargs['vdid'] = row[0]
        c = cherrypy.thread_data.db.sql_execute("""INSERT INTO `customers_virtual_domains`
            (`cid`, `vdid`)
        VALUES
            (%(cid)s, %(vdid)s)""", kwargs
        )
        cherrypy.thread_data.db.commit()

    def _add_virtual_user(self, **kwargs):
        c = cherrypy.thread_data.db.sql_execute("""INSERT INTO `virtual_users`
            (`domain_id`, `password` , `email`)
        VALUES
            (%(vdid)s, ENCRYPT(%(password)s, CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), %(email)s)""", kwargs
        )
        cherrypy.thread_data.db.commit()

    def _update_virtual_user_password(self, **kwargs):
        c = cherrypy.thread_data.db.sql_execute("""UPDATE virtual_users SET password=ENCRYPT(%(password)s, CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))) WHERE email=%(email)s""", kwargs)
        cherrypy.thread_data.db.commit()

    def is_domain_owner(self, domain_name, username):
        c = cherrypy.thread_data.db.sql_execute("""SELECT 1 FROM customers_virtual_domains 
        LEFT JOIN customers ON customers_virtual_domains.cid = customers.id 
        LEFT JOIN virtual_domains ON customers_virtual_domains.vdid = virtual_aliases.id 
        WHERE customer.username=%s AND virtual_domains.name = %s""" % (username, domain_name))
        return c.fetchone() is not None

    def is_user_owner(self, email, username):
        c = cherrypy.thread_data.db.sql_execute("""SELECT 1 FROM virtual_users
        LEFT JOIN customers_virtual_domains ON customers_virtual_domains.id = virtual_users.domain_id
        LEFT JOIN customers ON customers_virtual_domains.cid = customers.id 
        LEFT JOIN virtual_domains ON customers_virtual_domains.vdid = virtual_aliases.id 
        WHERE customer.username=%s AND virtual_users.email = %s""" % (email, domain_name))
        return c.fetchone() is not None

    def is_alias_owner(self, destination, username):
        c = cherrypy.thread_data.db.sql_execute("""SELECT 1 FROM 
        LEFT JOIN virtual_users ON virtual_users.id = virtual_aliases.vuid
        LEFT JOIN customers_virtual_domains ON customers_virtual_domains.id = virtual_users.domain_id
        LEFT JOIN customers ON customers_virtual_domains.cid = customers.id 
        LEFT JOIN virtual_domains ON customers_virtual_domains.vdid = virtual_aliases.id 
        WHERE customer.username=%s AND virtual_users.email = %s""" % (email, domain_name))
        return c.fetchone() is not None

    def _build_top_menu(self, params):
        url = '/'
        html = []
        for param in params:
            if param is None:
                continue
            url += param + '/'
            html.append('<a href="%s">%s</a>' % (url, param))
        return u'»'.join(html)

    def _delete_customer(self, customer_name):
        c = cherrypy.thread_data.db.sql_execute("""DELETE FROM customers WHERE username=%s""", (customer_name,))
        cherrypy.thread_data.db.commit()

    def _delete_virtual_domain(self, domain_name):
        c = cherrypy.thread_data.db.sql_execute("""DELETE FROM virtual_domains WHERE name=%s""", (domain_name,))
        cherrypy.thread_data.db.commit()

    def _delete_virtual_user(self, username):
        c = cherrypy.thread_data.db.sql_execute("""DELETE FROM virtual_users WHERE email=%s""", (username,))
        cherrypy.thread_data.db.commit()

    def _delete_virtual_alias(self, destination):
        c = cherrypy.thread_data.db.sql_execute("""DELETE FROM virtual_alias WHERE destination=%s""", (destination,))
        cherrypy.thread_data.db.commit()

    def _add_virtual_alias(self, **kwargs):
        c = cherrypy.thread_data.db.sql_execute("""INSERT INTO `virtual_aliases`
            (`domain_id`, vuid, `destination`)
        VALUES
            (%(vdid)s, %(vuid)s, %(destination)s);""", kwargs
        )
        cherrypy.thread_data.db.commit()

    def _get_menu_html(self, customer_menu=False, customer=None):
        html = u""
        if cherrypy.session.get("is_admin", False):
            html = self.__template_admin_menu_entrys
        if customer_menu:
            if cherrypy.session.get('is_admin', False):
                html += self.__template_customer_menu_entrys__admin_view % {'customer': customer}
            else:
                 html += self.__template_customer_menu_entrys
        return self.__template_menu % {
            "menu_entrys": html
        }

    def _get_virtual_users_table_html(self, customer, domain, vdid):
        tbody = ''
        c = self._get_virtual_users(vdid)
        while True:
            virtual_user = c.fetchone()
            if virtual_user is None:
                break;
            virtual_user['customer'] = customer
            virtual_user['domain'] = domain
            tbody += self.__template_virtual_users_table_entry % virtual_user

        return self.__template_virtual_users_table % {'tbody': tbody}

    def _get_virtual_aliases_table_html(self, customer, domain, email):
        tbody = ''
        c = self._get_virtual_aliases(email)
        while True:
            virtual_alias = c.fetchone()
            if virtual_alias is None:
                break;
            virtual_alias['customer'] = customer
            virtual_alias['domain'] = domain
            tbody += self.__template_virtual_aliases_table_entry % virtual_alias

        return self.__template_virtual_aliases_table % {'tbody': tbody}

    def _get_customers_table_html(self):
        tbody = ''
        c = self._get_customers()
        while True:
            customer = c.fetchone()
            if customer is None:
                break;
            tbody += self.__template_customers_table_entry % customer

        return self.__template_customers_table % {'tbody': tbody}

    @cherrypy.expose
    #@cherrypy.tools.authorize()
    @authorize()
    def users(self, param1=None, param2=None, param3=None, param4=None, **kwargs):
        return self.customer(cherrypy.session.get('username', None), "users", param1, param2, param3, param4, **kwargs)

    @cherrypy.expose
    #@cherrypy.tools.authorize()
    @authorize()
    def domains(self, param1=None, param2=None, param3=None, param4=None, **kwargs):
        return self.customer(cherrypy.session.get('username', None), 'domains', param1, param2, param3, param4, **kwargs)

    @cherrypy.expose
    #@cherrypy.tools.authorize(admin=True)
    @authorize(admin=True)
    def customers(self, param1=None, param2=None, param3=None, **kwargs):
        err_msg = ''
        html = ''
        password_class = ''
        username_class = ''
        email_class = ''
        if param1 == "add":
            if cherrypy.request.method == 'POST':
                username = kwargs['username']
                password = kwargs['password']
                password2 = kwargs['password2']
                email = kwargs['email']
                if password != password2:
                    err_msg += u"passwords don't match!"
                    password_class = 'error'
                else:
                    self._add_customer(username, password, email)
                    raise cherrypy.HTTPRedirect("/customers/" % kwargs)
        html= self.__template_add_customer % {
            'target': '/customers/add/', 
            'password_class': password_class,
            'username_class': username_class,
            'email_class': email_class
        }
        html += err_msg
        html += "<h1>Customers</h1>" + self._get_customers_table_html()
        return self.__template_index % {
            'html': self.__template_logged_in % {
                'menu':  self._get_menu_html(), 
                'top_menu': '',
                'html': html
                }
        }

    @cherrypy.expose
    #@cherrypy.tools.authorize(admin=True)
    @authorize(admin_or_owner=True)
    def customer(self, param1=None, param2=None, param3=None, param4=None, param5=None, param6=None, **kwargs):
        top_menu = u''
        err_msg = u''
        html = u''
        email_class = ''
        password_class = ''
        username_class = ''
        domain_class = ''
        destination_class = ''
        if param1 is not None:
            top_menu = self._build_top_menu(('customer', param1, param2, param3, param4, param5, param6))
            customer_name = param1
            customer = self._get_customer(customer_name)
            if customer is None:
                html = "Customer not found."
            else:
                if param2 == "change":
                    if cherrypy.request.method == 'POST':
                        kwargs['username'] = customer_name
                        if param3 == "pw":
                            if kwargs['password'] != kwargs['password2']:
                                err_msg += u"passwords don't match!"
                                email_class = 'error'
                            else:
                                self._update_customer_password(**kwargs)
                        elif param3 == "email":
                            if kwargs['password'] != kwargs['password2']:
                                err_msg += u"passwords don't match!"
                                email_class = 'error'
                            else:
                                self._update_customer(**kwargs)
                elif param2 == "delete":
                    if cherrypy.request.method == 'POST':
                        self._delete_customer(param1)
                        raise cherrypy.HTTPRedirect("/customers/")
                    html = self.__template_delete_form % {
                        'target': "/customer/%(customer)s/" % {'customer': customer_name},
                        'text': 'Do you really want to delete this customer?'
                    }
                    return self._build(html, top_menu, True, customer=customer_name)
                elif param2 == "add":
                    kwargs['username'] = customer_name
                    kwargs['cid'] = customer['id']
                    if param3 == "domain":
                        self._add_virtual_domain(**kwargs)
                    elif param3 == "user":
                        domain = self._get_virtual_domain(kwargs['domain'])
                        kwargs['vdid'] = domain['id']
                        kwargs['email'] = "%s@%s" % (kwargs['user'], kwargs['domain'])
                        self._add_virtual_user(**kwargs)
                    elif param3 == "alias":
                        domain = self._get_virtual_domain(kwargs['domain'])
                        kwargs['vdid'] = domain['id']
                        user = self._get_virtual_user(kwargs['email'])
                        kwargs['vuid'] = user['id']
                        self._add_virtual_alias(**kwargs)
                elif param2 == "delete":
                    if param3 == "domain":
                        if cherrypy.request.method == 'POST':
                            if "yes" in kwargs:
                                self._delete_virtual_domain(param4)
                            raise cherrypy.HTTPRedirect("/customer/" + "/".join(param1, param2))
                        html = self.__template_delete_form % {
                            'target': "/customer/%(customer)s/domain/delete/%(domain)s" % {
                                'customer': customer_name, 
                                'domain': param4
                             },
                            'text': 'Do you really want to delete this virtual user?'
                        }
                        return self._build(html, top_menu, True, customer=customer_name)
                    if param3 == "user":
                        if cherrypy.request.method == 'POST':
                            if "yes" in kwargs:
                                self._delete_virtual_user(param4)
                            raise cherrypy.HTTPRedirect("/customer/" + "/".join(param1, param2))
                        html = self.__template_delete_form % {
                            'target': "/customer/%(customer)s/domain/delete/%(user)s" % {
                                'customer': customer_name, 
                                'user': param4
                            },
                            'text': 'Do you really want to delete this virtual user?'
                        }
                        return self._build(html, top_menu, True, customer=customer_name)
                    elif param3 == "alias":
                        if cherrypy.request.method == 'POST':
                            if "yes" in kwargs:
                                self._delete_virtual_alias(param4)
                            raise cherrypy.HTTPRedirect("/customer/" + "/".join(param1, param2))
                        html = self.__template_delete_form % {
                            'target': "/customer/%(customer)s/domain/delete/%(alias)s" % {
                                'customer': customer_name, 
                                'alias': param4
                             },
                            'text': 'Do you really want to delete this virtual alias?'
                        }
                        return self._build(html, top_menu, True, customer=customer_name)

                elif param2 in ("virtual_user", "virtual_users", "user", "users"):
                    if param4 == "change" and param5 == "pw":
                        kwargs['email'] = param3
                        if kwargs['password'] != kwargs['password2']:
                            err_msg += u"passwords don't match!"
                            password_class = 'error'
                        else:
                            self._update_virtual_user_password(**kwargs)
                    else:
                        html = self._get_complete_users_table_html(username)
                        return self._build(html, top_menu, True, customer=customer_name)
                elif param2 in ("virtual_domain", "virtual_domains", "domain", "domains"):
                    if param3 == "delete":
                        if cherrypy.request.method == 'POST':
                            self._delete_virtual_domain(domain)
                            raise cherrypy.HTTPRedirect("/customer/%(customer)s/" % {'customer': param1})
                        html = self.__template_delete_form % {
                            'target': "/".join((param1, param2, param3, param4)),
                            'text': 'Do you really want to delete this virtual domain?'
                        }
                        return self._build(html, top_menu, True, customer=customer_name)
                    elif param3 is not None:
                        domain_name = param3
                        if param4 == "delete":
                            if cherrypy.request.method == 'POST':
                                if "yes" in kwargs:
                                    self._delete_virtual_user(domain_name)
                                raise cherrypy.HTTPRedirect("/customer" + "/".join((param1, param2)))
                            html = self.__template_delete_form % {
                                'target': "/customer/" + "/".join(param1, param2, param3, param4),
                                'text': 'Do you really want to delete this virtual user?'
                            }
                            return self._build(html, top_menu, True, customer=customer_name)
                        elif param4 is not None:
                            virtual_user_name = param4
                            if param5 == "delete":
                                if cherrypy.request.method == 'POST':
                                    if "yes" in kwargs:
                                        self._delete_virtual_alias(virtual_user_name)
                                    raise cherrypy.HTTPRedirect("/customer/" + "/".join((param1, param2, param4, param4)))
                                html = self.__template_delete_form % {
                                    'target': "/customer/" + "/".join((param1, param2, param3, param4)),
                                    'text': 'Do you really want to delete this virtual user?'
                                }
                                return self._build(html, top_menu, True, customer=customer_name)
                            if param6 == "delete":
                                if cherrypy.request.method == 'POST':
                                    self._delete_virtual_alias(param5)
                                    raise cherrypy.HTTPRedirect("/customer/" + "/".join((param1, param2, param3, param4, param5, param6)))
                                html = self.__template_delete_form % {
                                    'target': "/customer/" + "/".join((param1, param2, param3, param4, param5, param6)),
                                    'text': 'Do you really want to delete this virtual alias?'
                                }
                                return self._build(html, top_menu, True, customer=customer_name)
                            html = self.__template_virtual_user_change_pw_form % {
                                'username': param1, 
                                'name': virtual_user_name,
                                'password_class': password_class
                            }
                            html += self.__template_customer_add_virtual_alias_form % {
                                'username': param1, 
                                'email': virtual_user_name, 
                                'domain': domain_name,
                                'destination_class': destination_class
                            }
                            html += "<h1>Aliases</h1>" + self._get_virtual_aliases_table_html(customer_name, domain_name, virtual_user_name)
                            return self._build(html, top_menu, True, customer=customer_name)
                        else:
                            domain = self._get_virtual_domain(param3)
                            vdid = domain['id']
                            domain['username'] = param1
                            domain['username_class'] = username_class
                            domain['password_class'] = password_class
                            html = self.__template_customer_add_virtual_user_form % domain
                            html += "<h1>Users</h1>" + self._get_virtual_users_table_html(param1, param3, vdid)
                            return self._build(html, top_menu, True, customer=customer_name)
                    #else:
                    #    html = self._build(self.__template_customer_add_domain_form % customer, self._get_virtual_domains_table_html(param1), top_menu, True, customer=customer_name)
                    #    return html
                if err_msg == '' and param2 in ("add", "change"):
                    raise cherrypy.HTTPRedirect("/customer/%(username)s" % customer)
                customer['email_class'] = email_class
                customer['password_class'] = password_class
                customer['domain_class'] = domain_class
                html = "%s %s %s %s %s" % (err_msg, self.__template_customer_change_mail_form % customer, 
                    self.__template_customer_change_pw_form % customer, 
                    self.__template_customer_add_domain_form % customer, 
                    self._get_virtual_domains_table_html(param1))

        return self._build(html, top_menu, param1 is not None, customer=customer_name)

    def _build(self, html, top_menu='', customer_menu=False, customer=None):
        return self.__template_index % {
            'html': self.__template_logged_in % {
                'menu':  self._get_menu_html(customer_menu, customer=customer),
                'top_menu': top_menu, 
                'html': html
                }
        }

    def _get_virtual_domains_table_html(self, username):
        tbody = u''
        c = self._get_virtual_domains(username)
        while True:
            domain = c.fetchone()
            if domain is None:
                break;
            domain['customer'] = username
            tbody += self.__template_virtual_domains_table_entry % domain

        return self.__template_virtual_domains_table % {'tbody': tbody}


    def _get_complete_users_table_html(self, username):
        c = self._get_virtual_domains(username)
        domains = c.fetchall()
        html = u""
        for domain in domains:
            html += u"""<h2><a href="/customer/%(username)s/domain/%(domain_name)s">%(domain_name)s</a></h2>""" % {
                'username': username, 
                'domain_name': domain['name']
            }
            html += self._get_virtual_users_table_html(username, domain['name'], domain['id'])
        return html

    @cherrypy.expose
    def index(self, **kwargs):
        html = u''
        username_class = ''
        password_class = ''
        if cherrypy.request.method == 'POST':
            username = kwargs['username']
            password = kwargs['password']
            if self._auth_customer(username, password):
                cherrypy.session['username'] = username
                raise cherrypy.HTTPRedirect("/" % kwargs)
        if 'username' in cherrypy.session:
            html = self.__template_logged_in % {
                'top_menu': '',
                'menu':  self._get_menu_html(not cherrypy.session.get('is_admin', False)),
                'html': html
            }
        else:
            html = self.__template_login % {
                'target': '/',
                'username_class': username_class,
                'password_class': password_class
            }
        return self.__template_index % {'html': html}

    @cherrypy.expose
    def admin(self, **kwargs):
        html = u''
        username_class = ''
        password_class = ''
        if cherrypy.request.method == 'POST':
            username = kwargs['username']
            password = kwargs['password']
            if self._auth_admin(username, password):
                print "username", username
                cherrypy.session['username'] = username
                cherrypy.session['is_admin'] = True
                raise cherrypy.HTTPRedirect("/admin/" % kwargs)
            else:
                html = "auth failed!"
        if 'username' in cherrypy.session:
            html = self.__template_logged_in % {
                'top_menu': '',
                'menu': self._get_menu_html(), 
                'html': html
            }
        else:
            html = self.__template_login % {
                'target': '/admin/',
                'username_class': username_class,
                'password_class': password_class
            }
        return self.__template_index % {'html': html}

    @cherrypy.expose
    def logout(self, **kwargs):
        if 'username' in cherrypy.session:
             cherrypy.session.clear()
        raise cherrypy.HTTPRedirect("/")


cherrypy.config.update(
    {
            #'server.socket_port': 8080,
            #'server.socket_host': '127.0.0.1',
            'server.socket_file': "/tmp/ucms",
            'engine.autoreload.on': True,
            'log.access_file': './logs/access.log',
            'log.error_file': './logs/error.log'
    }
)

# CherryPy autoreload must be disabled for the flup server to work
cherrypy.tree.mount(UCMS(), "/", config={
    "/": {
            'tools.sessions.on': True,
            'tools.sessions.storage_type': 'file',
            'tools.sessions.storage_path': os.path.join(os.path.abspath(os.getcwd()), 'sessions')
        }
    }
)
