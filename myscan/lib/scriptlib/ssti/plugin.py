from myscan.lib.scriptlib.ssti import rand
import re
import itertools
import base64
import collections
import threading
import time
import copy
from myscan.config import plugin_set

def _recursive_update(d, u):
    # Update value of a nested dictionary of varying depth
    
    for k, v in u.items():
        if d.get(k) is None:
            if isinstance(v,dict):
                d[k]={}
            else:
                d[k]=""
        if isinstance(v, dict):
            for k1,v1 in v.items():
                d[k][k1]=v1
        else:
            d[k] = u[k]

    return d


class Plugin(object):
    def __init__(self):
        self.plugin = self.__class__.__name__
        self.actions = {}
        self.contexts = []
        self.language_init()
        self.init()
    def generate_payloads(self):
        render_action = self.actions.get('render')
        test_payloads=[]
        for prefix, suffix in self._generate_contexts():

            # Prepare base operation to be evalued server-side
            expected = render_action.get('test_render_expected')

            payload = render_action.get('test_render')
            header_rand = rand.randint_n(10)
            header = render_action.get('header') % ({'header': header_rand})
            trailer_rand = rand.randint_n(10)
            trailer = render_action.get('trailer') % ({'trailer': trailer_rand})
            # if expected == self.render(
            #         code=payload,
            #         header=header,
            #         trailer=trailer,
            #         header_rand=header_rand,
            #         trailer_rand=trailer_rand,
            #         prefix=prefix,
            #         suffix=suffix
            # ):
            #     print("OK"*20)

            test_payloads.append(
                (
                self.render(
                    code=payload,
                    header=header,
                    trailer=trailer,
                    header_rand=header_rand,
                    trailer_rand=trailer_rand,
                    prefix=prefix,
                    suffix=suffix
            ),
                expected,
                self.plugin,
            )
            )
        return test_payloads
    def _generate_contexts(self):
        contexts=[]
        for ctx in self.contexts:
            if not int(plugin_set.get("ssti").get("level"))>=ctx.get("level"):
                continue
            suffix = ctx.get('suffix', '') % ()

            # If the context has no closures, generate one closure with a zero-length string
            if ctx.get('closures'):
                closures = self._generate_closures(ctx)

                # print('%s plugin is testing %s*%s code context escape with %i variations%s' % (
                #     self.plugin,
                #     repr(ctx.get('prefix', '%(closure)s') % ({'closure': ''})).strip("'"),
                #     repr(suffix).strip("'"),
                #     len(closures),
                #     ' (level %i)' % (ctx.get('level', 1))
                # )
                #          )
            else:
                closures = ['']

            for closure in closures:
                # Format the prefix with closure
                prefix = ctx.get('prefix', '%(closure)s') % ({'closure': closure})

                contexts.append((prefix, suffix))
        return contexts
    def _generate_closures(self, ctx):

        closures_dict = ctx.get('closures', { '0' : [] })

        closures = [ ]

        # Loop all the closure names
        for ctx_closure_level, ctx_closure_matrix in closures_dict.items():
            # Skip any closure list which is above the required level
            if int(plugin_set.get("ssti").get("level")) >= ctx_closure_level:
                closures += [ ''.join(x) for x in itertools.product(*ctx_closure_matrix) ]

        closures = sorted(set(closures), key=len)
        # Return it
        return closures
    def update_actions(self, actions):

        # Recursively update actions on the instance
        self.actions = _recursive_update(
            copy.deepcopy(self.actions), copy.deepcopy(actions)
        )

    def set_contexts(self, contexts):

        # Update contexts on the instance
        self.contexts = contexts

    def render(self, code, **kwargs):

        # If header == '', do not send headers
        header_template = kwargs.get('header')
        header = ''
        if header_template != '':

            header_template = kwargs.get('header')
            if not header_template:
                header_template = self.actions.get('render', {}).get('header')

            if header_template:
                header_rand = kwargs.get('header_rand')

                if '%(header)s' in header_template:
                    header = header_template % ({'header': header_rand})
                else:
                    header = header_template

        # If trailer == '', do not send headers
        trailer_template = kwargs.get('trailer')
        trailer = ''

        if trailer_template != '':

            trailer_template = kwargs.get('trailer')
            if not trailer_template:
                trailer_template = self.actions.get('render', {}).get('trailer')

            if trailer_template:
                trailer_rand = kwargs.get('trailer_rand')

                if '%(trailer)s' in trailer_template:
                    trailer = trailer_template % ({'trailer': trailer_rand})
                else:
                    trailer = trailer_template

        payload_template = kwargs.get('render')
        if not payload_template:
            payload_template = self.actions.get('render', {}).get('render')
        if not payload_template:
            # Exiting, actions.render.render is not set
            return None

        payload = payload_template % ({'code': code})

        prefix = kwargs.get('prefix',"")
        suffix = kwargs.get('suffix', "")

        blind = kwargs.get('blind', False)

        injection = header + payload + trailer
        return injection
        # Save the average HTTP request time of rendering in order
        # to better tone the blind request timeouts.
    def language_init(self):
        pass

    def init(self):
        # To be overriden. This can call self.update_actions
        # and self.set_contexts

        pass
    def get(self, key, default = None):
        return self.actions.get(key, default)