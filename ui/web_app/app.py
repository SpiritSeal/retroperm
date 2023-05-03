from flask import Flask, render_template, request
from flask_cors import CORS
from threading import Thread

app = Flask(__name__)
CORS(app)


def my_backend_function(file, option1, option2):
    # This function represents your actual backend function that takes the file and some options
    # as input and returns some HTML. In this example, we'll just return a placeholder HTML string.
    return f"<h1>File: {file.filename}, Option 1: {option1}, Option 2: {option2}</h1>"


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        option1 = request.form.get('option1')
        option2 = request.form.get('option2')

        # Start a new thread to run the backend function asynchronously
        def run_backend():
            result = my_backend_function(file, option1, option2)
            # Update the result in the global variable once it's complete
            global backend_result
            backend_result = result

        global backend_result
        backend_result = None
        Thread(target=run_backend).start()

        return render_template('index.html', submitted=True)

    return render_template('index.html', submitted=False)


@app.route('/result')
def result():
    global backend_result
    if backend_result is not None:
        return backend_result
    else:
        return "Backend function still running..."


if __name__ == '__main__':
    app.run(debug=True)
