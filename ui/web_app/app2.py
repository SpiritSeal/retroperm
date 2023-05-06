from flask import Flask, request, jsonify, render_template
import threading
import time
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        # save the file to a temporary location
        file.save('temp/' + file.filename)

        # run your analysis on the file in a separate thread
        thread = threading.Thread(target=run_analysis, args=('temp/' + file.filename,))
        thread.start()

        # return a response to the user immediately
        return jsonify({'message': 'Analysis started'})

def run_analysis(filename):
    # simulate running the analysis for 5 seconds
    time.sleep(5)

    # delete the temporary file
    os.remove(filename)

    # update the front-end with the results
    with app.test_request_context():
        socketio.emit('result', {'result': 'Your analysis result goes here'})

if __name__ == '__main__':
    from flask_socketio import SocketIO, emit
    socketio = SocketIO(app)

    # start the server and listen for socketio events
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
