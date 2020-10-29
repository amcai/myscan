#!/usr/bin/env python3
# @Time    : 2020-04-21
# @Author  : caicai
# @File    : importssti.py


from myscan.lib.scriptlib.ssti.engines.jinja2 import Jinja2
from myscan.lib.scriptlib.ssti.engines.dot import Dot
from myscan.lib.scriptlib.ssti.engines.twig import Twig
from myscan.lib.scriptlib.ssti.engines.ejs import Ejs
from myscan.lib.scriptlib.ssti.engines.erb import Erb
from myscan.lib.scriptlib.ssti.engines.mako import Mako
from myscan.lib.scriptlib.ssti.engines.marko import Marko
from myscan.lib.scriptlib.ssti.engines.nunjucks import Nunjucks
from myscan.lib.scriptlib.ssti.engines.pug import Pug
from myscan.lib.scriptlib.ssti.engines.slim import Slim
from myscan.lib.scriptlib.ssti.engines.smarty import Smarty
from myscan.lib.scriptlib.ssti.engines.tornado import Tornado
from myscan.lib.scriptlib.ssti.engines.velocity import Velocity
from myscan.lib.scriptlib.ssti.engines.freemarker import Freemarker
from myscan.lib.scriptlib.ssti.engines.dust import Dust
from myscan.lib.scriptlib.ssti.languages.javascript import Javascript
from myscan.lib.scriptlib.ssti.languages.php import Php
from myscan.lib.scriptlib.ssti.languages.python import Python
from myscan.lib.scriptlib.ssti.languages.ruby import Ruby
from myscan.lib.core.data import others,logger

plugins = [
    Smarty,
    Mako,
    Python,
    Tornado,
    Jinja2,
    Twig,
    Freemarker,
    Velocity,
    Slim,
    Erb,
    Pug,
    Nunjucks,
    Dot,
    Dust,
    Marko,
    Javascript,
    Php,
    Ruby,
    Ejs
]

def importssti():
    try:
        test_payloads=[]
        for plugin in plugins:
            current_plugin = plugin()
            test_payloads+=current_plugin.generate_payloads()
        others.ssti_payloads=test_payloads
        # logger.debug("import ssti payloads success")
    except Exception as ex:
        logger.warning("import ssti payloads error:{}".format(ex))

