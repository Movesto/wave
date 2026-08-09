import shlex, os
from flask import request
def h(): os.system("ping " + shlex.quote(request.args.get('host')))
