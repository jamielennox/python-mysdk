# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging

from keystoneclient import baseclient
from keystoneclient.openstack.common import jsonutils
from keystoneclient.v2_0 import endpoints as v2endpoints
from keystoneclient.v2_0 import roles as v2roles
from keystoneclient.v2_0 import services as v2services
from keystoneclient.v2_0 import tenants as v2tenants
from keystoneclient.v2_0 import tokens as v2tokens
from keystoneclient.v2_0 import users as v2users
from keystoneclient.v3.contrib import trusts as v3trusts
from keystoneclient.v3 import credentials as v3credentials
from keystoneclient.v3 import domains as v3domains
from keystoneclient.v3 import endpoints as v3endpoints
from keystoneclient.v3 import groups as v3groups
from keystoneclient.v3 import policies as v3policies
from keystoneclient.v3 import projects as v3projects
from keystoneclient.v3 import roles as v3roles
from keystoneclient.v3 import services as v3services
from keystoneclient.v3 import users as v3users


class BaseIdentityClient(baseclient.Client):
    service_type = 'identity'

    # The following methods will hopefully get cleaned up in client
    @staticmethod
    def _decode_body(resp):
        if resp.text:
            try:
                body_resp = jsonutils.loads(resp.text)
            except (ValueError, TypeError):
                body_resp = None
                logging.debug("Could not decode JSON from body: %s"
                              % resp.text)
        else:
            logging.debug("No body was returned.")
            body_resp = None

        return body_resp

    def request(self, url, method, **kwargs):
        """Send an http request with the specified characteristics.

        Wrapper around requests.request to handle tasks such as
        setting headers, JSON encoding/decoding, and error handling.
        """

        try:
            kwargs['json'] = kwargs.pop('body')
        except KeyError:
            pass

        resp = super(BaseIdentityClient, self).request(url, method, **kwargs)
        return resp, self._decode_body(resp)


class V2IdentityClient(BaseIdentityClient):
    endpoint_type = 'admin'
    version = (2, 0)

    def __init__(self, *args, **kwargs):
        super(V2IdentityClient, self).__init__(*args, **kwargs)

        self.endpoints = v2endpoints.EndpointManager(self)
        self.roles = v2roles.RoleManager(self)
        self.services = v2services.ServiceManager(self)
        self.tenants = v2tenants.TenantManager(self)
        self.tokens = v2tokens.TokenManager(self)
        self.users = v2users.UserManager(self)


class V3IdentityClient(BaseIdentityClient):
    version = (3, 0)

    def __init__(self, *args, **kwargs):
        super(V3IdentityClient, self).__init__(*args, **kwargs)

        self.credentials = v3credentials.CredentialManager(self)
        self.endpoints = v3endpoints.EndpointManager(self)
        self.domains = v3domains.DomainManager(self)
        self.groups = v3groups.GroupManager(self)
        self.policies = v3policies.PolicyManager(self)
        self.projects = v3projects.ProjectManager(self)
        self.roles = v3roles.RoleManager(self)
        self.services = v3services.ServiceManager(self)
        self.users = v3users.UserManager(self)
        self.trusts = v3trusts.TrustManager(self)


class InvalidInputObj(Exception):
    pass


class InvalidVersion(Exception):
    pass


class Resource(object):

    def __init__(self, manager=None):
        self.manager = manager

    @classmethod
    def create(cls, obj, **kwargs):
        raise InvalidInputObj

    def render(self, target):
        raise InvalidInputObj


class ProxyManager(object):
    resource = None

    def __init__(self, manager):
        self.manager = manager

    def create(self, obj):
        obj_dict = obj.render(self.manager)
        new_obj = self.manager.create(obj_dict)
        return self.resource.create(new_obj, manager=self)

    def get(self, id):
        new_obj = self.manager.get(id)
        return self.resource.create(new_obj)

    def update(self, obj):
        obj_dict = obj.render(self.manager)
        upd_obj = self.manager.update(obj_dict)

        if upd_obj:
            return self.resource.create(upd_obj, manager=self)

    def delete(self, obj):
        obj_dict = obj.render(self.manager)
        return self.manager.delete(obj_dict)

    def list(self):
        objs = self.manager.list()
        return [self.resource.create(obj) for obj in objs]


class Role(Resource):

    def __init__(self, id, name, **kwargs):
        super(Role, self).__init__(**kwargs)
        self.id = id
        self.name = name

    @classmethod
    def create(cls, obj, **kwargs):
        if isinstance(obj, v2roles.Role):
            return cls(obj.id, obj.name, **kwargs)
        elif isinstance(obj, v3roles.Role):
            return cls(obj.id, obj.name, **kwargs)

        return super(Role, cls).create(obj, **kwargs)

    def render(self, obj):
        if isinstance(obj, v2roles.RoleManager):
            return {'id': self.id, 'name': self.name}
        elif isinstance(obj, v3roles.RoleManager):
            return {'id': self.id, 'name': self.name}

        return super(Role, self).render(obj)


class RoleManager(ProxyManager):
    resource = Role


class User(Resource):

    DEFAULT_DOMAIN_ID = 'default'

    def __init__(self, id, name, email=None, enabled=True,
                 domain_id=None, **kwargs):
        super(User, self).__init__(**kwargs)

        self.id = id
        self.name = name
        self.email = email
        self.enabled = enabled
        self.domain_id = domain_id

    @classmethod
    def create(cls, obj, **kwargs):
        if isinstance(obj, v2users.User):
            domain_id = cls.DEFAULT_DOMAIN_ID,
        elif isinstance(obj, v3users.User):
            domain_id = obj.domain_id
        else:
            return super(User, cls).create(obj, **kwargs)

        return cls(obj.id, obj.name,
                   email=obj.email,
                   enabled=obj.enabled,
                   domain_id=domain_id,
                   **kwargs)

    def render(self, obj):
        user = {'id': self.id,
                'name': self.name,
                'email': self.email,
                'enabled': self.enabled}

        if isinstance(obj, v2users.UserManager):
            if self.domain_id and self.domain_id != self.DEFAULT_DOMAIN_ID:
                raise InvalidVersion()

            return user

        elif isinstance(obj, v3users.UserManager):
            user['domain_id'] = self.domain_id
            return user

        return super(User, self).render(obj)


class UserManager(ProxyManager):
    resource = User


class Project(Resource):

    def __init__(self, id, name, description=None, domain_id=None,
                 enabled=True, **kwargs):
        super(Project, self).__init__(self, **kwargs)

        self.id = id
        self.name = name
        self.domain_id = domain_id
        self.enabled = enabled

    @classmethod
    def create(cls, obj, **kwargs):
        if isinstance(obj, v2tenants.Tenant):
            domain_id = None
        elif isinstance(obj, v3projects.Project):
            domain_id = obj.domain_id
        else:
            return super(Project, cls).create(obj, **kwargs)

        return cls(obj.id,
                   obj.name,
                   description=obj.description,
                   domain_id=domain_id,
                   enabled=obj.enabled,
                   **kwargs)

    def render(self, obj):
        project = {}

        if isinstance(obj, v2tenants.TenantManager):
            if self.domain_id:
                raise InvalidVersion()
        elif isinstance(obj, v3projects.ProjectManager):
            project['domain_id'] = obj.domain_id
        else:
            return super(Project, self).render(obj)

        project['id'] = self.id
        project['name'] = self.name
        project['email'] = self.email
        project['enabled'] = self.enabled

        return project


class ProjectManager(ProxyManager):
    resource = Project


class IdentityClient(object):

    def __init__(self, session):
        if session.get_endpoint(service_type='identity',
                                version=(3, 0),
                                endpoint_type='public'):
            client = V3IdentityClient(session)

            self.projects = ProjectManager(client.projects)

        elif session.get_endpoint(service_type='identity',
                                  version=(2, 0),
                                  endpoint_type='admin'):
            client = V2IdentityClient(session)

            self.projects = ProjectManager(client.tenants)

        else:
            raise Exception('No valid clients')

        self.roles = RoleManager(client.roles)
        self.users = UserManager(client.users)


if __name__ == '__main__':
    from keystoneclient import session

    logging.basicConfig(level=logging.DEBUG)

    from keystoneclient.auth.identity import v2
    auth = v2.Password(auth_url='http://localhost:5000/v2.0',
                       username='jamie', password='jamie',
                       tenant_name='demo')

    # from keystoneclient.auth.identity import v3
    # auth = v3.Password(auth_url='http://localhost:5000/v3',
    #                    username='jamie', password='jamie',
    #                    user_domain_id='default',
    #                    project_domain_id='default', project_name='demo')

    sess = session.Session(auth)

    ident = IdentityClient(sess)

    projects = ident.projects.list()
    for project in projects:
        print "Project", project.id, project.name

    # users = ident.users.list()
    # for user in users:
    #     print "User", user

    # roles = ident.roles.list()
    # for role in roles:
    #     print "Role= id: %s, name: %s" % (role.id, role.name)
