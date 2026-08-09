import os
from flask import request
def h(): os.system("ping " + request.args.get('host'))
