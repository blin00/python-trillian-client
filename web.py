#!/usr/bin/env python3

from flask import Flask
from client import TrillianLogClient


app = Flask(__name__)
client = TrillianLogClient('localhost:8090')

@app.route('/')
def hello():
    return 'hello flask!'

@app.route('/append', methods=['PUT'])
def append():
    # TODO
    return 'not implemented'
