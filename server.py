from flask import Flask, request
from flask_cors import CORS
import ML_backend as api



app = Flask(__name__)
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/', methods=['POST'])
def serve():
    url = request.form['url']
    print(url)
    value = api.callabale_info(url, [])
    return value[1]



if __name__=='__main__':
    app.run()