#!/usr/bin/env/python

#imports
import os
import numpy as np
import pandas as pd
import requests
import time

from flask import Flask, flash, redirect, url_for, request, render_template
from werkzeug.utils import secure_filename

application = Flask(__name__)

UPLOAD_FOLDER = 'upload/'

URL = 'https://www.virustotal.com/vtapi/v2/file/report'

API_KEY = 'cdccfa9dc48fcfd4e39598112a100f8d268caab1cdfcc9a3e0fedc4dbd757151'


