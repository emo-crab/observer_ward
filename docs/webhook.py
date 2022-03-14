from flask import Flask, request

app = Flask(__name__)


@app.route('/webhook', methods=['POST'])
def xray_webhook():
    print(request.json)
    return 'ok'


if __name__ == '__main__':
    app.run()
