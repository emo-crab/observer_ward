from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook", methods=['POST'])
def observer_ward_webhook():
    print("Authorization: ",request.headers.get("Authorization"))
    print(request.json)
    return 'ok'


if __name__ == '__main__':
    app.run()